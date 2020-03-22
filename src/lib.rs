//  Copyright (c) 2019 Alain Brenzikofer
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

//! # Encointer Scheduler Module
//!
//! provides functionality for
//! - scheduling ceremonies with their different phases
//! - dispatch transition functions upon phase change
//!

#![cfg_attr(not(feature = "std"), no_std)]

use support::{
    decl_event, decl_module, decl_storage,
    dispatch::Result,
    ensure,
    storage::StorageValue,
};
use system::ensure_signed;
use rstd::prelude::*;
use runtime_io::misc::print_utf8;
use codec::{Decode, Encode};
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

pub trait Trait: system::Trait 
{
    type Event: From<Event> + Into<<Self as system::Trait>::Event>;
}

pub type CeremonyIndexType = u32;

#[derive(Encode, Decode, Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub enum CeremonyPhaseType {
    REGISTERING,
    ASSIGNING,
    ATTESTING,
}

impl Default for CeremonyPhaseType {
    fn default() -> Self {
        CeremonyPhaseType::REGISTERING
    }
}

// This module's storage items.
decl_storage! {
    trait Store for Module<T: Trait> as EncointerScheduler {
        // caution: index starts with 1, not 0! (because null and 0 is the same for state storage)
        CurrentCeremonyIndex get(current_ceremony_index) config(): CeremonyIndexType;
        LastCeremonyBlock get(last_ceremony_block): T::BlockNumber;
        CurrentPhase get(current_phase): CeremonyPhaseType = CeremonyPhaseType::REGISTERING;
        CeremonyMaster get(ceremony_master) config(): T::AccountId;
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        fn deposit_event() = default;

        pub fn next_phase(origin) -> Result {
            let sender = ensure_signed(origin)?;
            ensure!(sender == <CeremonyMaster<T>>::get(), "only the CeremonyMaster can call this function");
            let current_phase = <CurrentPhase>::get();
            let current_ceremony_index = <CurrentCeremonyIndex>::get();

            let next_phase = match current_phase {
                CeremonyPhaseType::REGISTERING => {
                        //Self::assign_meetups()?;
                        CeremonyPhaseType::ASSIGNING
                },
                CeremonyPhaseType::ASSIGNING => {
                        CeremonyPhaseType::ATTESTING
                },
                CeremonyPhaseType::ATTESTING => {
                        //Self::issue_rewards()?;
                        let next_ceremony_index = match current_ceremony_index.checked_add(1) {
                            Some(v) => v,
                            None => 0, //deliberate wraparound
                        };
                        //Self::purge_registry(current_ceremony_index)?;
                        <CurrentCeremonyIndex>::put(next_ceremony_index);
                        CeremonyPhaseType::REGISTERING
                },
            };

            <CurrentPhase>::put(next_phase);
            Self::deposit_event(Event::PhaseChangedTo(next_phase));
            print_utf8(b"phase changed");
            Ok(())
        }
    }
}

decl_event!(
    pub enum Event {
        PhaseChangedTo(CeremonyPhaseType),
    }
);

#[cfg(test)]
mod tests;
