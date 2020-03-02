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

//! # Encointer Ceremonies Module
//!
//! The Encointer Ceremonies module provides functionality for 
//! - registering for upcoming ceremony
//! - meetup assignment
//! - witness registry
//! - issuance of basic income
//!

#![cfg_attr(not(feature = "std"), no_std)]

use support::{decl_module, decl_storage, decl_event, ensure,
	storage::{StorageDoubleMap, StorageMap, StorageValue},
	traits::Currency,
	dispatch::Result};
use system::{ensure_signed, ensure_root};

use rstd::prelude::*;
use rstd::cmp::min;

use sr_primitives::traits::{Verify, Member, CheckedAdd, IdentifyAccount};
use sr_primitives::MultiSignature;
use runtime_io::misc::print_utf8;

use codec::{Codec, Encode, Decode};

#[cfg(feature = "std")]
use serde::{Serialize, Deserialize};

pub trait Trait: system::Trait + balances::Trait {
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
    type Public: IdentifyAccount<AccountId = Self::AccountId>;
    type Signature: Verify<Signer = Self::Public> + Member + Decode + Encode;
}

const SINGLE_MEETUP_INDEX: u64 = 1;

pub type CeremonyIndexType = u32;
pub type ParticipantIndexType = u64;
pub type MeetupIndexType = u64;
pub type WitnessIndexType = u64;

#[derive(Encode, Decode, Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub enum CeremonyPhaseType {
	REGISTERING, 
	ASSIGNING,
	WITNESSING, 	
}
impl Default for CeremonyPhaseType {
    fn default() -> Self { CeremonyPhaseType::REGISTERING }
}

#[derive(Encode, Decode, Copy, Clone, PartialEq, Eq, Default, Debug)]
pub struct Witness<Signature, AccountId> {
	pub claim: ClaimOfAttendance<AccountId>,
	pub signature: Signature,
	pub public: AccountId,
}

#[derive(Encode, Decode, Copy, Clone, PartialEq, Eq, Default, Debug)]
pub struct ClaimOfAttendance<AccountId> {
	pub claimant_public: AccountId,
	pub ceremony_index: CeremonyIndexType,
	pub meetup_index: MeetupIndexType,
	pub number_of_participants_confirmed: u32,
}

// This module's storage items.
decl_storage! {
	trait Store for Module<T: Trait> as EncointerCeremonies {
		// everyone who registered for a ceremony
		// caution: index starts with 1, not 0! (because null and 0 is the same for state storage)
		ParticipantRegistry get(participant_registry): double_map CeremonyIndexType, blake2_256(ParticipantIndexType) => T::AccountId;
		ParticipantIndex get(participant_index): double_map CeremonyIndexType, blake2_256(T::AccountId) => ParticipantIndexType;
		ParticipantCount get(participant_count): ParticipantIndexType;

		// all meetups for each ceremony mapping to a vec of participants
		// caution: index starts with 1, not 0! (because null and 0 is the same for state storage)
		MeetupRegistry get(meetup_registry): double_map CeremonyIndexType, blake2_256(MeetupIndexType) => Vec<T::AccountId>;
		MeetupIndex get(meetup_index): double_map CeremonyIndexType, blake2_256(T::AccountId) => MeetupIndexType;
		MeetupCount get(meetup_count): MeetupIndexType;

		// collect fellow meetup participants accounts who witnessed key account
		// caution: index starts with 1, not 0! (because null and 0 is the same for state storage)
		WitnessRegistry get(witness_registry): double_map CeremonyIndexType, blake2_256(WitnessIndexType) => Vec<T::AccountId>;
		WitnessIndex get(witness_index): double_map CeremonyIndexType, blake2_256(T::AccountId) => WitnessIndexType;
		WitnessCount get(witness_count): WitnessIndexType;
		// how many peers does each participants observe at their meetup
		MeetupParticipantCountVote get(meetup_participant_count_vote): double_map CeremonyIndexType, blake2_256(T::AccountId) => u32;

		// caution: index starts with 1, not 0! (because null and 0 is the same for state storage)
		CurrentCeremonyIndex get(current_ceremony_index) config(): CeremonyIndexType;
		
		LastCeremonyBlock get(last_ceremony_block): T::BlockNumber;
		CurrentPhase get(current_phase): CeremonyPhaseType = CeremonyPhaseType::REGISTERING;

		CeremonyReward get(ceremony_reward) config(): T::Balance;
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
						Self::assign_meetups();
						CeremonyPhaseType::ASSIGNING
				},
				CeremonyPhaseType::ASSIGNING => {
						CeremonyPhaseType::WITNESSING
				},
				CeremonyPhaseType::WITNESSING => {
						Self::issue_rewards();
						let next_ceremony_index = match current_ceremony_index.checked_add(1) {
							Some(v) => v,
							None => 0, //deliberate wraparound
						};
						Self::purge_registry(current_ceremony_index);
						<CurrentCeremonyIndex>::put(next_ceremony_index);									
						CeremonyPhaseType::REGISTERING
				},
			};

			<CurrentPhase>::put(next_phase);
			Self::deposit_event(RawEvent::PhaseChangedTo(next_phase));
			print_utf8(b"phase changed");
			Ok(())
		}

		pub fn register_participant(origin) -> Result {
			let sender = ensure_signed(origin)?;
			ensure!(<CurrentPhase>::get() == CeremonyPhaseType::REGISTERING,
				"registering participants can only be done during REGISTERING phase");

			let cindex = <CurrentCeremonyIndex>::get();

			if <ParticipantIndex<T>>::exists(&cindex, &sender) {
				return Err("already registered participant")
			}

			let count = <ParticipantCount>::get();
			
			let new_count = count.checked_add(1).
            	ok_or("[EncointerCeremonies]: Overflow adding new participant to registry")?;
			
			<ParticipantRegistry<T>>::insert(&cindex, &new_count, &sender);
			<ParticipantIndex<T>>::insert(&cindex, &sender, &new_count);
			<ParticipantCount>::put(new_count);

			Ok(())
		}

		pub fn register_witnesses(origin, witnesses: Vec<Witness<T::Signature, T::AccountId>>) -> Result {
			let sender = ensure_signed(origin)?;
			ensure!(<CurrentPhase>::get() == CeremonyPhaseType::WITNESSING,			
				"registering witnesses can only be done during WITNESSING phase");
			let cindex = <CurrentCeremonyIndex>::get();
			let meetup_index = Self::meetup_index(&cindex, &sender);
			let mut meetup_participants = Self::meetup_registry(&cindex, &meetup_index);
			ensure!(meetup_participants.contains(&sender), "origin not part of this meetup");
			meetup_participants.retain(|x| x != &sender);
			let num_registered = meetup_participants.len();
			let num_signed = witnesses.len();
			ensure!(num_signed <= num_registered, "can\'t have more witnesses than other meetup participants");
			let mut verified_witness_accounts = vec!();
			let mut claim_n_participants = 0u32;
			for w in 0..num_signed {
				let witness = &witnesses[w];
				let witness_account = &witnesses[w].public;
				if meetup_participants.contains(witness_account) == false { 
					print_utf8(b"ignoring witness that isn't a meetup participant");
					continue };
				if witness.claim.ceremony_index != cindex { 
					print_utf8(b"ignoring claim with wrong ceremony index");
					continue };
				if witness.claim.meetup_index != meetup_index { 
					print_utf8(b"ignoring claim with wrong meetup index");
					continue };
				if Self::verify_witness_signature(witness.clone()).is_err() { 
					print_utf8(b"ignoring witness with bad signature");
					continue };
				// witness is legit. insert it!
				verified_witness_accounts.insert(0, witness_account.clone());
				// is it a problem if this number isn't equal for all claims? Guess not.
				claim_n_participants = witness.claim.number_of_participants_confirmed;
			}
			if verified_witness_accounts.len() == 0 {
				return Err("no valid witnesses found");
			}

			let count = <WitnessCount>::get();
			let mut idx = count+1;

			if <WitnessIndex<T>>::exists(&cindex, &sender) {
				idx = <WitnessIndex<T>>::get(&cindex, &sender);
			} else {
				let new_count = count.checked_add(1).
            		ok_or("[EncointerCeremonies]: Overflow adding new witness to registry")?;
				<WitnessCount>::put(new_count);
			}
			<WitnessRegistry<T>>::insert(&cindex, &idx, &verified_witness_accounts);
			<WitnessIndex<T>>::insert(&cindex, &sender, &idx);
			<MeetupParticipantCountVote<T>>::insert(&cindex, &sender, &claim_n_participants);
			Ok(())
		}
	}
}

decl_event!(
	pub enum Event<T> where AccountId = <T as system::Trait>::AccountId {
		PhaseChangedTo(CeremonyPhaseType),
		ParticipantRegistered(AccountId),
	}
);


impl<T: Trait> Module<T> {
	fn purge_registry(index: CeremonyIndexType) -> Result {
		<ParticipantRegistry<T>>::remove_prefix(&index);
		<ParticipantIndex<T>>::remove_prefix(&index);
		<ParticipantCount>::put(0);
		<MeetupRegistry<T>>::remove_prefix(&index);
		<MeetupIndex<T>>::remove_prefix(&index);
		<MeetupCount>::put(0);
		<WitnessRegistry<T>>::remove_prefix(&index);
		<WitnessIndex<T>>::remove_prefix(&index);
		<WitnessCount>::put(0);
		<MeetupParticipantCountVote<T>>::remove_prefix(&index);
		Ok(())
	}
	
	// this function is expensive, so it should later be processed off-chain within SubstraTEE-worker
	fn assign_meetups() -> Result {
		// for PoC1 we're assigning one single meetup with the first 12 participants only
		//ensure!(<CurrentPhase>::get() == CeremonyPhaseType::ASSIGNING,
		//		"registering meetups can only be done during ASSIGNING phase");
		let cindex = <CurrentCeremonyIndex>::get();		
		let pcount = <ParticipantCount>::get();		
		let mut meetup = vec!();
		
		for p in 1..min(pcount+1, 12+1) {
			let participant = <ParticipantRegistry<T>>::get(&cindex, &p);
			meetup.insert(meetup.len(), participant.clone());
			<MeetupIndex<T>>::insert(&cindex, &participant, &SINGLE_MEETUP_INDEX);
		}
		<MeetupRegistry<T>>::insert(&cindex, &SINGLE_MEETUP_INDEX, &meetup);
		<MeetupCount>::put(1);		
		Ok(())
	}

	fn verify_witness_signature(witness: Witness<T::Signature, T::AccountId>) -> Result {
		ensure!(witness.public != witness.claim.claimant_public, "witness may not be self-signed");
		match witness.signature.verify(&witness.claim.encode()[..], &witness.public) {
			true => Ok(()),
			false => Err("witness signature is invalid")
		}
	}

	// this function takes O(n) for n meetups, so it should later be processed off-chain within 
	// SubstraTEE-worker together with the entire registry
	// as this function can only be called by the ceremony state machine, it could actually work out fine
	// on-chain. It would just delay the next block once per ceremony cycle.
	fn issue_rewards() -> Result {
		ensure!(Self::current_phase() == CeremonyPhaseType::WITNESSING,			
			"issuance can only be called at the end of WITNESSING phase");
		let cindex = Self::current_ceremony_index();
		let meetup_count = Self::meetup_count();
		let reward = Self::ceremony_reward();		
		ensure!(meetup_count == 1, "registry must contain exactly one meetup for PoC1");

		for m in 0..meetup_count {
			// first, evaluate votes on how many participants showed up
			let (n_confirmed, n_honest_participants) = match Self::ballot_meetup_n_votes(SINGLE_MEETUP_INDEX) {
				Some(nn) => nn,
				_ => {
					print_utf8(b"skipping meetup because votes for num of participants are not dependable");
					continue;
				},
			};
			let mut meetup_participants = Self::meetup_registry(&cindex, &SINGLE_MEETUP_INDEX);
			for p in meetup_participants {
				if Self::meetup_participant_count_vote(&cindex, &p) != n_confirmed {
					print_utf8(b"skipped participant because of wrong participant count vote");
					continue; }
				let witnesses = Self::witness_registry(&cindex, 
					&Self::witness_index(&cindex, &p));
				if witnesses.len() < (n_honest_participants - 1) as usize || witnesses.is_empty() {
					print_utf8(b"skipped participant because of too few witnesses");
					continue; }
				let mut has_witnessed = 0u32;
				for w in witnesses {
					let w_witnesses = Self::witness_registry(&cindex, 
					&Self::witness_index(&cindex, &w));
					if w_witnesses.contains(&p) {
						has_witnessed += 1;
					}
				}
				if has_witnessed < (n_honest_participants - 1) {
					print_utf8(b"skipped participant because didn't testify for honest peers");
					continue; }					
				// TODO: check that p also signed others
				// participant merits reward
				print_utf8(b"participant merits reward");
				let old_balance = <balances::Module<T>>::free_balance(&p);
				let new_balance = old_balance.checked_add(&reward)
					.expect("Balance should never overflow");
				<balances::Module<T> as Currency<_>>::make_free_balance_be(&p, new_balance);
			}
		}
		Ok(())
	}

	fn ballot_meetup_n_votes(meetup_idx: MeetupIndexType) -> Option<(u32, u32)> {
		let cindex = Self::current_ceremony_index();
		let meetup_participants = Self::meetup_registry(&cindex, &meetup_idx);
		// first element is n, second the count of votes for n
		let mut n_vote_candidates: Vec<(u32,u32)> = vec!(); 
		for p in meetup_participants {
			let this_vote = match Self::meetup_participant_count_vote(&cindex, &p) {
				n if n > 0 => n,
				_ => continue,
			};
			match n_vote_candidates.iter().position(|&(n,c)| n == this_vote) {
				Some(idx) => n_vote_candidates[idx].1 += 1,
				_ => n_vote_candidates.insert(0, (this_vote,1)),
			};
		}
		if n_vote_candidates.is_empty() { return None; }
		// sort by descending vote count
		n_vote_candidates.sort_by(|a,b| b.1.cmp(&a.1));
		if n_vote_candidates[0].1 < 3 {
			return None;
		}
		Some(n_vote_candidates[0])
	}
}


#[cfg(test)]
mod tests;

