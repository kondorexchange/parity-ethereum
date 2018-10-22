// Copyright 2015-2018 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(unused_imports)]

use std::collections::BTreeMap;
use std::sync::{Arc, Weak};

use block::ExecutedBlock;
use client::{EngineClient, BlockInfo};
use engines::{Engine, Seal, signer::EngineSigner, ForkChoice};
use ethjson;
use ethjson::spec::ValidatorSet as ValidatorSpec;
use ethkey::Password;
use account_provider::AccountProvider;
use error::{BlockError, Error};
use header::{Header, ExtendedHeader};
use machine::EthereumMachine;
use parking_lot::RwLock;
use ethereum_types::{H256, H520, Address, U128, U256};
use rlp::{self, Decodable, DecoderError, Encodable, RlpStream, Rlp};

use super::validator_set::{new_validator_set, SimpleList, ValidatorSet};

// The maximum number of epochs for whom we will store the validator set.
const MAX_VALIDATOR_CACHE_SIZE: usize = 10;

/// A temporary fixed seal code. The seal has only a single field, containing this string.
// TODO: Use a threshold signature of the block.
const SEAL: &str = "Honey Badger isn't afraid of seals!";

/// Returns `true` if the validator set found in the HBBFT config JSON file is a hardcoded list of
/// addresses (i.e. the contents of the validator set does not depend on a smart contract).
fn is_validator_set_constant(validator_spec: &ValidatorSpec) -> bool {
    match validator_spec {
        ValidatorSpec::List(_) => true,
        ValidatorSpec::Contract(_) => false,
        ValidatorSpec::SafeContract(_) => false,
        ValidatorSpec::Multi(ref validator_specs) => {
            validator_specs
                .values()
                .all(|validator_spec| is_validator_set_constant(validator_spec))
        },
    }
}

/// `Hbbft` params.
pub struct HbbftParams {
    /// Whether to use millisecond timestamp
    pub millisecond_timestamp: bool,
    pub validators: Box<ValidatorSet>,
    pub validator_set_is_constant: bool,
}

impl From<ethjson::spec::HbbftParams> for HbbftParams {
    fn from(p: ethjson::spec::HbbftParams) -> Self {
        let validator_set_is_constant = is_validator_set_constant(&p.validators);
        HbbftParams {
            millisecond_timestamp: p.millisecond_timestamp,
            validators: new_validator_set(p.validators),
            validator_set_is_constant,
        }
    }
}


/// Stores the validator set for `MAX_VALIDATOR_CACHE_SIZE` number of epochs.
#[derive(Default)]
struct ValidatorCache(BTreeMap<usize, Vec<Address>>);

impl ValidatorCache {
    fn new() -> Self {
        ValidatorCache::default()
    }

    fn insert(&mut self, epoch: usize, validators: Vec<Address>) {
        if self.0.contains_key(&epoch) {
            return;
        }
        if self.0.len() >= MAX_VALIDATOR_CACHE_SIZE {
            let oldest_epoch = *self.0.keys().take(1).next().unwrap();
            let _ = self.0.remove(&oldest_epoch);
        }
        self.0.insert(epoch, validators);
    }

    fn get_validators_for_epoch(&self, epoch: usize) -> Option<&Vec<Address>> {
        self.0.get(&epoch)
    }
}

/// An engine which does not provide any consensus mechanism, just seals blocks internally.
/// Only seals blocks which have transactions.
pub struct Hbbft {
    machine: EthereumMachine,
    client: RwLock<Option<Weak<EngineClient>>>,
    signer: RwLock<EngineSigner>,
    pub millisecond_timestamp: bool,
    validators: Box<ValidatorSet>,
    validator_set_is_constant: bool,
    validator_set_cache: ValidatorCache,
}

impl Hbbft {
    /// Returns new instance of Hbbft over the given state machine.
    pub fn new(params: HbbftParams, machine: EthereumMachine) -> Self {
        Hbbft {
            machine,
            client: RwLock::new(None),
            signer: Default::default(),
            millisecond_timestamp: params.millisecond_timestamp,
            validators: params.validators,
            validator_set_is_constant: params.validator_set_is_constant,
            validator_set_cache: ValidatorCache::new(),
        }
    }
}

impl Engine<EthereumMachine> for Hbbft {
	fn name(&self) -> &str {
		"Hbbft"
	}

	fn machine(&self) -> &EthereumMachine { &self.machine }

	fn seals_internally(&self) -> Option<bool> { Some(true) }

	fn seal_fields(&self, _header: &Header) -> usize { 1 }

	fn should_miner_prepare_blocks(&self) -> bool { false }

	fn generate_seal(&self, block: &ExecutedBlock, _parent: &Header) -> Seal {
		debug!(target: "engine", "####### Hbbft::generate_seal: Called for block: {:?}.", block);
		// match self.client.read().as_ref().and_then(|weak| weak.upgrade()) {
		// 	Some(client) => {
		// 		let best_block_header_num = (*client).as_full_client().unwrap().best_block_header().number();

		// 		debug!(target: "engine", "###### block.header.number(): {}, best_block_header_num: {}",
		// 			block.header.number(), best_block_header_num);

		// 		if block.header.number() > best_block_header_num {
		// 			Seal::Regular(vec![
		// 				rlp::encode(&SEAL),
		// 				// rlp::encode(&(&H520::from(&b"Another Field"[..]) as &[u8])),
		// 			])
		// 		} else {
		// 			debug!(target: "engine", "Hbbft::generate_seal: Returning `Seal::None`.");
		// 			Seal::None
		// 		}
		// 	},
		// 	None => {
		// 		debug!(target: "engine", "No client ref available.");
		// 		Seal::None
		// 	},
		// }

		Seal::Regular(vec![
			rlp::encode(&SEAL),
		])
	}

	fn verify_local_seal(&self, header: &Header) -> Result<(), Error> {
		if header.seal() == &[rlp::encode(&SEAL)] {
			Ok(())
		} else {
			Err(BlockError::InvalidSeal.into())
		}
	}

    // Called from `OpenBlock::new()`.
    fn on_new_block(
        &self,
        block: &mut ExecutedBlock,
        is_first_block_in_epoch: bool,
        _ancestry: &mut Iterator<Item=ExtendedHeader>,
    ) -> Result<(), Error> {
        if !is_first_block_in_epoch{
            return Ok(());
        }
        if self.validator_set_is_constant {
            return Ok(());
        }
        // If we are using a smart contract to store the validator set (as opposed to
        // configuring a constant validator set using the engine's spec file),
        // `ValidatorSet::on_epoch_begin(&self)` will call the smart contract's
        // `finalizeChange` function resulting in any pending changes to the smart
        // contract's validator set being applied.
        let header = block.header.clone();
        let is_genesis_block = header.number() == 0;
        let mut call_finalize_change = |safe_contract_addr, data| {
            let gas = U256::max_value();
            self.machine
                .execute_as_system(block, safe_contract_addr, gas, Some(data))
                .map_err(|e| format!("{}", e))
        };
        self.validators.on_epoch_begin(is_genesis_block, &header, &mut call_finalize_change)
    }

	fn open_block_header_timestamp(&self, parent_timestamp: u64) -> u64 {
		use std::{time, cmp};

		let dur = time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap_or_default();
		let mut now = dur.as_secs();
		if self.millisecond_timestamp {
			now = now * 1000 + dur.subsec_millis() as u64;
		}
		cmp::max(now, parent_timestamp)
	}

	fn is_timestamp_valid(&self, header_timestamp: u64, parent_timestamp: u64) -> bool {
		header_timestamp >= parent_timestamp
	}

	fn fork_choice(&self, new: &ExtendedHeader, current: &ExtendedHeader) -> ForkChoice {
		// debug!("######## ENGINE-HBBFT::FORK_CHOICE: \n    NEW: {:?}, \n    OLD: {:?}", new, current);
		use ::parity_machine::TotalScoredHeader;
		if new.header.number() > current.header.number() {
			debug_assert!(new.total_score() > current.total_score());
			ForkChoice::New
		} else if new.header.number() < current.header.number() {
			debug_assert!(new.total_score() < current.total_score());
			ForkChoice::Old
		} else {
			// The entire header won't always be identical but the score should be:
			debug_assert_eq!(new.total_score(), current.total_score());
			ForkChoice::Old
		}
	}

	fn register_client(&self, client: Weak<EngineClient>) {
		*self.client.write() = Some(client.clone());
	}

	fn set_signer(&self, ap: Arc<AccountProvider>, address: Address, password: Password) {
		self.signer.write().set(ap, address, password);
	}
}

#[cfg(test)]
mod tests {
	use std::sync::Arc;
	use ethereum_types::{H520, Address};
	use test_helpers::get_temp_state_db;
	use spec::Spec;
	use header::Header;
	use block::*;
	use engines::Seal;

	#[test]
	fn hbbft_can_seal() {
		let spec = Spec::new_hbbft();
		let engine = &*spec.engine;
		let db = spec.ensure_db_good(get_temp_state_db(), &Default::default()).unwrap();
		let genesis_header = spec.genesis_header();
		let last_hashes = Arc::new(vec![genesis_header.hash()]);
		let b = OpenBlock::new(engine, Default::default(), false, db, &genesis_header, last_hashes, Address::default(), (3141562.into(), 31415620.into()), vec![], false, &mut Vec::new().into_iter()).unwrap();
		let b = b.close_and_lock().unwrap();
		if let Seal::Regular(seal) = engine.generate_seal(b.block(), &genesis_header) {
			assert!(b.try_seal(engine, seal).is_ok());
		} else {
			panic!("Failed to seal block.");
		}
	}

	#[test]
	fn hbbft_cant_verify() {
		let engine = Spec::new_hbbft().engine;
		let mut header: Header = Header::default();

		assert!(engine.verify_block_basic(&header).is_ok());

		header.set_seal(vec![::rlp::encode(&H520::default())]);

		assert!(engine.verify_block_unordered(&header).is_ok());
	}
}
