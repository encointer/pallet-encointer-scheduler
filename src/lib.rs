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
//! - attestation registry
//! - issuance of basic income
//!

#![cfg_attr(not(feature = "std"), no_std)]

use support::{decl_module, decl_storage, decl_event, ensure,
	storage::{StorageDoubleMap, StorageMap, StorageValue},
	traits::{Currency, Randomness},
	dispatch::Result};
use system::{ensure_signed, ensure_root};

use rstd::prelude::*;
use rstd::cmp::min;

use primitives::{Blake2Hasher, Hasher};
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
const REPUTATION_LIFETIME: u32 = 1;

pub type CeremonyIndexType = u32;
pub type ParticipantIndexType = u64;
pub type MeetupIndexType = u64;
pub type AttestationIndexType = u64;

#[derive(Encode, Decode, Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub enum CeremonyPhaseType {
	REGISTERING, 
	ASSIGNING,
	ATTESTING, 	
}
impl Default for CeremonyPhaseType {
    fn default() -> Self { CeremonyPhaseType::REGISTERING }
}

#[derive(Encode, Decode, Copy, Clone, PartialEq, Eq, Default, Debug)]
pub struct Attestation<Signature, AccountId> {
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

#[derive(Encode, Decode, Copy, Clone, PartialEq, Eq, Default, Debug)]
pub struct ProofOfAttendance<Signature, AccountId> {
	pub prover_public: AccountId,
	pub ceremony_index: CeremonyIndexType,
	pub attendee_public: AccountId,
	pub attendee_signature: Signature
}


// This module's storage items.
decl_storage! {
	trait Store for Module<T: Trait> as EncointerCeremonies {
		// everyone who registered for a ceremony
		// caution: index starts with 1, not 0! (because null and 0 is the same for state storage)
		ParticipantRegistry get(participant_registry): double_map CeremonyIndexType, blake2_256(ParticipantIndexType) => T::AccountId;
		ParticipantIndex get(participant_index): double_map CeremonyIndexType, blake2_256(T::AccountId) => ParticipantIndexType;
		ParticipantCount get(participant_count): ParticipantIndexType;
		IsFormerVerifiedAttendee get(is_former_verified_attendee): double_map CeremonyIndexType, blake2_256(T::AccountId) => bool;

		// everyone who participated successfully in a previous ceremony
		// caution: index starts with 1, not 0! (because null and 0 is the same for state storage)
		IsVerifiedAttendee get(is_verified_attendee): double_map CeremonyIndexType, blake2_256(T::AccountId) => bool;
 
		// all meetups for each ceremony mapping to a vec of participants
		// caution: index starts with 1, not 0! (because null and 0 is the same for state storage)
		MeetupRegistry get(meetup_registry): double_map CeremonyIndexType, blake2_256(MeetupIndexType) => Vec<T::AccountId>;
		MeetupIndex get(meetup_index): double_map CeremonyIndexType, blake2_256(T::AccountId) => MeetupIndexType;
		MeetupCount get(meetup_count): MeetupIndexType;

		// collect fellow meetup participants accounts who attestationed key account
		// caution: index starts with 1, not 0! (because null and 0 is the same for state storage)
		AttestationRegistry get(attestation_registry): double_map CeremonyIndexType, blake2_256(AttestationIndexType) => Vec<T::AccountId>;
		AttestationIndex get(attestation_index): double_map CeremonyIndexType, blake2_256(T::AccountId) => AttestationIndexType;
		AttestationCount get(attestation_count): AttestationIndexType;
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
						CeremonyPhaseType::ATTESTING
				},
				CeremonyPhaseType::ATTESTING => {
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

		pub fn register_participant(origin, proof: Option<ProofOfAttendance<T::Signature, T::AccountId>>) -> Result {
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
			if let Some(p) = proof {
				ensure!(sender == p.prover_public, "supplied proof is not proving sender");
				if Self::verify_attendee_signature(p.clone()).is_err() { 
					return Err("proof of attendance has bad signature");
				};
				ensure!(p.ceremony_index < cindex, "proof is acausal"); 
				ensure!(p.ceremony_index >= cindex-REPUTATION_LIFETIME, "proof is outdated");
				ensure!(Self::is_verified_attendee(p.ceremony_index, &p.attendee_public),
					"former attendance has not been verified");
				// this reputation must now be burned so it can not be used again
				<IsVerifiedAttendee<T>>::insert(&p.ceremony_index, &p.attendee_public, false);
				Self::register_former_verified_attendee(cindex, &sender);
			};
			<ParticipantRegistry<T>>::insert(&cindex, &new_count, &sender);
			<ParticipantIndex<T>>::insert(&cindex, &sender, &new_count);
			<ParticipantCount>::put(new_count);
			Ok(())
		}

		pub fn register_attestations(origin, attestations: Vec<Attestation<T::Signature, T::AccountId>>) -> Result {
			let sender = ensure_signed(origin)?;
			ensure!(<CurrentPhase>::get() == CeremonyPhaseType::ATTESTING,			
				"registering attestations can only be done during ATTESTING phase");
			let cindex = <CurrentCeremonyIndex>::get();
			let meetup_index = Self::meetup_index(&cindex, &sender);
			let mut meetup_participants = Self::meetup_registry(&cindex, &meetup_index);
			ensure!(meetup_participants.contains(&sender), "origin not part of this meetup");
			meetup_participants.retain(|x| x != &sender);
			let num_registered = meetup_participants.len();
			let num_signed = attestations.len();
			ensure!(num_signed <= num_registered, "can\'t have more attestations than other meetup participants");
			let mut verified_attestation_accounts = vec!();
			let mut claim_n_participants = 0u32;
			for w in 0..num_signed {
				let attestation = &attestations[w];
				let attestation_account = &attestations[w].public;
				if meetup_participants.contains(attestation_account) == false { 
					print_utf8(b"ignoring attestation that isn't a meetup participant");
					continue };
				if attestation.claim.ceremony_index != cindex { 
					print_utf8(b"ignoring claim with wrong ceremony index");
					continue };
				if attestation.claim.meetup_index != meetup_index { 
					print_utf8(b"ignoring claim with wrong meetup index");
					continue };
				if Self::verify_attestation_signature(attestation.clone()).is_err() { 
					print_utf8(b"ignoring attestation with bad signature");
					continue };
				// attestation is legit. insert it!
				verified_attestation_accounts.insert(0, attestation_account.clone());
				// is it a problem if this number isn't equal for all claims? Guess not.
				claim_n_participants = attestation.claim.number_of_participants_confirmed;
			}
			if verified_attestation_accounts.len() == 0 {
				return Err("no valid attestations found");
			}

			let count = <AttestationCount>::get();
			let mut idx = count+1;

			if <AttestationIndex<T>>::exists(&cindex, &sender) {
				idx = <AttestationIndex<T>>::get(&cindex, &sender);
			} else {
				let new_count = count.checked_add(1).
            		ok_or("[EncointerCeremonies]: Overflow adding new attestation to registry")?;
				<AttestationCount>::put(new_count);
			}
			<AttestationRegistry<T>>::insert(&cindex, &idx, &verified_attestation_accounts);
			<AttestationIndex<T>>::insert(&cindex, &sender, &idx);
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
		<AttestationRegistry<T>>::remove_prefix(&index);
		<AttestationIndex<T>>::remove_prefix(&index);
		<AttestationCount>::put(0);
		<MeetupParticipantCountVote<T>>::remove_prefix(&index);
		Ok(())
	}

	/* this is for a more recent revision of substrate....
	fn random_permutation(elements: Vec<u8>) -> Vec<u8> {
		let random_seed = <system::Module<T>>::random_seed();
		let out = Vec::with_capacity(elements.len());
		let n = elements.len();
		for i in 0..n {
			let new_random = (random_seed, i)
				.using_encoded(|b| Blake2Hasher::hash(b))
				.using_encoded(|mut b| u64::decode(&mut b))
				.expect("Hash must be bigger than 8 bytes; Qed");
			let elem = elements.remove(new_random % elements.len());
			out.push(elem);
		}
		out
	}
	*/

	// this function is expensive, so it should later be processed off-chain within SubstraTEE-worker
	// currently the complexity is O(n) where n is the number of registered participants
	fn assign_meetups() -> Result {
		let cindex = <CurrentCeremonyIndex>::get();		
		let pcount = <ParticipantCount>::get();		

		let mut reputables = Vec::with_capacity(pcount as usize);
		let mut newbies = Vec::with_capacity(pcount as usize);
		
		// TODO: upfront random permutation
		for p in 1..=pcount {
			let participant = <ParticipantRegistry<T>>::get(&cindex, &p);
			// FIXME: the cindex==1 test is only valid before we have multiple currencies
			if cindex == 1 || Self::is_former_verified_attendee(&cindex, &participant) {
				reputables.push(participant);
			} else {
				newbies.push(participant);
			}
		}
		let mut n = reputables.len();
		n += min(newbies.len(), n/4);
		let n_meetups = n/12 + 1;
		let mut meetups = Vec::with_capacity(n_meetups);
		let mut meetup_n_rep = vec![0; n_meetups];
		for i in 0..n_meetups {
			meetups.push(Vec::with_capacity(12))
		}
		// first, evenly assign reputables to meetups
		for (i, p) in reputables.iter().enumerate() {
			meetups[i % n_meetups].push(p);
			meetup_n_rep[i % n_meetups] += 1;
		}
		// now, distribute newbies, complying with newbie limit per meetup
		// FIXME: stop after skipping n_meetups newbies
		for (i, p) in newbies.iter().enumerate() {
			let _idx = i % n_meetups;
			if meetups[_idx].len() < meetup_n_rep[_idx]*4/3 {
				meetups[i % n_meetups].push(p);
			} else {
				print_utf8(b"had to skip one newbie");
			}
		}
		// purge meetups that are too small
		let mut toosmall = Vec::with_capacity(n_meetups);
		for (i, m) in meetups.iter().enumerate() {
			if m.len() < 3 {
				toosmall.push(i);
				print_utf8(b"one meetup can't take place because it is too small");
			}
		}
		for i in toosmall { meetups.remove(i); }
		// FIXME: with nightly we could do: meetups.drain_filter(|x| x.len() < 3).collect::<Vec<_>>();
		
		// commit result to state
		<MeetupCount>::put(n_meetups as MeetupIndexType);	
		for (i, m) in meetups.iter().enumerate() {
			let _idx = (i+1) as MeetupIndexType;
			for p in meetups[i].iter() {
				<MeetupIndex<T>>::insert(&cindex, p, &_idx);
			}				
			<MeetupRegistry<T>>::insert(&cindex, &_idx, meetups[i].clone());
		}
		Ok(())
	}

	fn verify_attestation_signature(attestation: Attestation<T::Signature, T::AccountId>) -> Result {
		ensure!(attestation.public != attestation.claim.claimant_public, "attestation may not be self-signed");
		match attestation.signature.verify(&attestation.claim.encode()[..], &attestation.public) {
			true => Ok(()),
			false => Err("attestation signature is invalid")
		}
	}

	fn register_verified_attendee(cindex: CeremonyIndexType, sender: &T::AccountId) {
		<IsVerifiedAttendee<T>>::insert(&cindex, &sender, true);
	} 
	
	fn register_former_verified_attendee(cindex: CeremonyIndexType, sender: &T::AccountId) {
		<IsFormerVerifiedAttendee<T>>::insert(&cindex, &sender, true);
	} 

	fn verify_attendee_signature(proof: ProofOfAttendance<T::Signature, T::AccountId>) -> Result {
		match proof.attendee_signature.verify(
			&(proof.prover_public, proof.ceremony_index).encode()[..], 
			&proof.attendee_public) {
				true => Ok(()),
				false => Err("attendee signature is invalid")
		}
	}


	// this function takes O(n) for n meetups, so it should later be processed off-chain within 
	// SubstraTEE-worker together with the entire registry
	// as this function can only be called by the ceremony state machine, it could actually work out fine
	// on-chain. It would just delay the next block once per ceremony cycle.
	fn issue_rewards() -> Result {
		ensure!(Self::current_phase() == CeremonyPhaseType::ATTESTING,			
			"issuance can only be called at the end of ATTESTING phase");
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
				let attestations = Self::attestation_registry(&cindex, 
					&Self::attestation_index(&cindex, &p));
				if attestations.len() < (n_honest_participants - 1) as usize || attestations.is_empty() {
					print_utf8(b"skipped participant because of too few attestations");
					continue; }
				let mut has_attestationed = 0u32;
				for w in attestations {
					let w_attestations = Self::attestation_registry(&cindex, 
					&Self::attestation_index(&cindex, &w));
					if w_attestations.contains(&p) {
						has_attestationed += 1;
					}
				}
				if has_attestationed < (n_honest_participants - 1) {
					print_utf8(b"skipped participant because didn't testify for honest peers");
					continue; }					
				// TODO: check that p also signed others
				// participant merits reward
				print_utf8(b"participant merits reward");
				let old_balance = <balances::Module<T>>::free_balance(&p);
				let new_balance = old_balance.checked_add(&reward)
					.expect("Balance should never overflow");
				<balances::Module<T> as Currency<_>>::make_free_balance_be(&p, new_balance);
				
				Self::register_verified_attendee(cindex, &p);
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

