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




//extern crate externalities;
//extern crate test_client;
//extern crate node_primitives;

use super::*;
use crate::{GenesisConfig, Module, Trait};
use support::{impl_outer_event, impl_outer_origin, parameter_types, assert_ok};
use sr_primitives::traits::{Verify, Member, CheckedAdd, IdentifyAccount};
use sr_primitives::{Perbill, traits::{IdentityLookup, BlakeTwo256}, testing::Header};
use std::{collections::HashSet, cell::RefCell};
use externalities::set_and_run_with_externalities;
use primitives::{H256, Blake2Hasher, Pair, Public, sr25519};
use support::traits::{Currency, Get, FindAuthor, LockIdentifier};
use sr_primitives::weights::Weight;
use node_primitives::{AccountId, Signature};
use test_client::AccountKeyring;

const NONE: u64 = 0;
const REWARD: Balance = 1000;

thread_local! {
    static EXISTENTIAL_DEPOSIT: RefCell<u64> = RefCell::new(0);
}
pub type BlockNumber = u64;
pub type Balance = u64;

type TestWitness = Witness<Signature, AccountId>;

pub struct ExistentialDeposit;
impl Get<u64> for ExistentialDeposit {
    fn get() -> u64 {
        EXISTENTIAL_DEPOSIT.with(|v| *v.borrow())
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TestRuntime;

impl Trait for TestRuntime {
    type Event = ();
    type Public = <MultiSignature as Verify>::Signer;
    type Signature = MultiSignature;
}

pub type EncointerCeremonies = Module<TestRuntime>;

parameter_types! {
    pub const BlockHashCount: u64 = 250;
    pub const MaximumBlockWeight: u32 = 1024;
    pub const MaximumBlockLength: u32 = 2 * 1024;
    pub const AvailableBlockRatio: Perbill = Perbill::one();
}
impl system::Trait for TestRuntime {
    type Origin = Origin;
    type Index = u64;
    type Call = ();
    type BlockNumber = BlockNumber;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = AccountId;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
    type Event = ();
    type BlockHashCount = BlockHashCount;
    type MaximumBlockWeight = MaximumBlockWeight;
    type MaximumBlockLength = MaximumBlockLength;
    type AvailableBlockRatio = AvailableBlockRatio;
    type Version = ();
}

pub type System = system::Module<TestRuntime>;

parameter_types! {
    pub const TransferFee: Balance = 0;
    pub const CreationFee: Balance = 0;
    pub const TransactionBaseFee: u64 = 0;
    pub const TransactionByteFee: u64 = 0;
}
impl balances::Trait for TestRuntime {
    type Balance = Balance;
    type OnFreeBalanceZero = ();
    type OnNewAccount = ();
    type Event = ();
    type TransferPayment = ();
    type DustRemoval = ();
    type ExistentialDeposit = ExistentialDeposit;
    type TransferFee = TransferFee;
    type CreationFee = CreationFee;
}
pub type Balances = balances::Module<TestRuntime>;

type AccountPublic = <Signature as Verify>::Signer;

pub struct ExtBuilder;

impl ExtBuilder {
    pub fn build() -> runtime_io::TestExternalities {
        let mut storage = system::GenesisConfig::default().build_storage::<TestRuntime>().unwrap();
        balances::GenesisConfig::<TestRuntime> {
            balances: vec![],
            vesting: vec![],
        }.assimilate_storage(&mut storage).unwrap();		
        GenesisConfig::<TestRuntime> {
            current_ceremony_index: 1,
            ceremony_reward: REWARD,
            ceremony_master: get_accountid(test_client::AccountKeyring::Alice),
        }.assimilate_storage(&mut storage).unwrap();		
        runtime_io::TestExternalities::from(storage)
    }
}

impl_outer_origin!{
    pub enum Origin for TestRuntime {}
}

fn meetup_claim_sign(claimant: AccountId, witness: AccountKeyring, n_participants: u32) -> TestWitness {
    let claim = ClaimOfAttendance {
        claimant_public: claimant.clone(),
        ceremony_index: 1,
        meetup_index: SINGLE_MEETUP_INDEX,
        number_of_participants_confirmed: n_participants,
    };
    TestWitness { 
        claim: claim.clone(),
        signature: Signature::from(witness.sign(&claim.encode())),
        public: get_accountid(witness),
    }
}

fn register_alice_bob_ferdie() {
    assert_ok!(EncointerCeremonies::register_participant(Origin::signed(get_accountid(AccountKeyring::Alice))));
    assert_ok!(EncointerCeremonies::register_participant(Origin::signed(get_accountid(AccountKeyring::Bob))));
    assert_ok!(EncointerCeremonies::register_participant(Origin::signed(get_accountid(AccountKeyring::Ferdie))));
}

fn register_charlie_dave_eve() {
    assert_ok!(EncointerCeremonies::register_participant(Origin::signed(get_accountid(AccountKeyring::Charlie))));
    assert_ok!(EncointerCeremonies::register_participant(Origin::signed(get_accountid(AccountKeyring::Dave))));
    assert_ok!(EncointerCeremonies::register_participant(Origin::signed(get_accountid(AccountKeyring::Eve))));
}

fn gets_witnessed_by(claimant: AccountId, witnesses: Vec<AccountKeyring>, n_participants: u32) {
    let mut testimonials: Vec<TestWitness> = vec!();
    for w in witnesses {
        testimonials.insert(0, 
            meetup_claim_sign(claimant.clone(), w.clone(), n_participants));
        
    }
    assert_ok!(EncointerCeremonies::register_witnesses(
            Origin::signed(claimant),
            testimonials.clone()));	
}

fn get_accountid(pair: AccountKeyring) -> AccountId {
    AccountPublic::from(pair.public()).into_account()
}

#[test]
fn ceremony_phase_statemachine_works() {
    ExtBuilder::build().execute_with(|| {
        let master = AccountId::from(AccountKeyring::Alice);
        assert_eq!(EncointerCeremonies::current_phase(), CeremonyPhaseType::REGISTERING);
        assert_eq!(EncointerCeremonies::current_ceremony_index(), 1);
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        assert_eq!(EncointerCeremonies::current_phase(), CeremonyPhaseType::ASSIGNING);
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        assert_eq!(EncointerCeremonies::current_phase(), CeremonyPhaseType::WITNESSING);
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        assert_eq!(EncointerCeremonies::current_phase(), CeremonyPhaseType::REGISTERING);
        assert_eq!(EncointerCeremonies::current_ceremony_index(), 2);						
    });
}

#[test]
fn registering_participant_works() {
    ExtBuilder::build().execute_with(|| {
        let alice = AccountId::from(AccountKeyring::Alice);
        let bob = AccountId::from(AccountKeyring::Bob);
        let cindex = EncointerCeremonies::current_ceremony_index();
        assert_eq!(EncointerCeremonies::participant_count(), 0);
        assert_ok!(EncointerCeremonies::register_participant(Origin::signed(alice.clone())));
        assert_eq!(EncointerCeremonies::participant_count(), 1);
        assert_ok!(EncointerCeremonies::register_participant(Origin::signed(bob.clone())));
        assert_eq!(EncointerCeremonies::participant_count(), 2);
        assert_eq!(EncointerCeremonies::participant_index(&cindex, &bob), 2);
        assert_eq!(EncointerCeremonies::participant_registry(&cindex, &1), alice);
        assert_eq!(EncointerCeremonies::participant_registry(&cindex, &2), bob);
    });
}

#[test]
fn registering_participant_twice_fails() {
    ExtBuilder::build().execute_with(|| {
        let alice = AccountId::from(AccountKeyring::Alice);
        assert_ok!(EncointerCeremonies::register_participant(Origin::signed(alice.clone())));
        assert!(EncointerCeremonies::register_participant(Origin::signed(alice.clone())).is_err());
    });
}

#[test]
fn ceremony_index_and_purging_registry_works() {
    ExtBuilder::build().execute_with(|| {
        let master = AccountId::from(AccountKeyring::Alice);
        let alice = AccountId::from(AccountKeyring::Alice);
        let cindex = EncointerCeremonies::current_ceremony_index();
        assert_ok!(EncointerCeremonies::register_participant(Origin::signed(alice.clone())));
        assert_eq!(EncointerCeremonies::participant_registry(&cindex, &1), alice);
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        // now assigning
        assert_eq!(EncointerCeremonies::participant_registry(&cindex, &1), alice);
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        // now witnessing
        assert_eq!(EncointerCeremonies::participant_registry(&cindex, &1), alice);
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        // now again registering
        let new_cindex = EncointerCeremonies::current_ceremony_index();
        assert_eq!(new_cindex, cindex+1);
        assert_eq!(EncointerCeremonies::participant_count(), 0);
        assert_eq!(EncointerCeremonies::participant_registry(&cindex, &1), AccountId::default());
        assert_eq!(EncointerCeremonies::participant_index(&cindex, &alice), NONE);
    });
}

#[test]
fn registering_participant_in_wrong_phase_fails() {
    ExtBuilder::build().execute_with(|| {
        let master = AccountId::from(AccountKeyring::Alice);
        let alice = AccountId::from(AccountKeyring::Alice);
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        assert_eq!(EncointerCeremonies::current_phase(), CeremonyPhaseType::ASSIGNING);
        assert!(EncointerCeremonies::register_participant(Origin::signed(alice.clone())).is_err());
    });
}

#[test]
fn assigning_meetup_works() {
    ExtBuilder::build().execute_with(|| {
        let master = AccountId::from(AccountKeyring::Alice);
        let alice = AccountId::from(AccountKeyring::Alice);
        let bob = AccountId::from(AccountKeyring::Bob);
        let ferdie = AccountId::from(AccountKeyring::Ferdie);
        let cindex = EncointerCeremonies::current_ceremony_index();
        assert_ok!(EncointerCeremonies::register_participant(Origin::signed(alice.clone())));
        assert_ok!(EncointerCeremonies::register_participant(Origin::signed(bob.clone())));
        assert_ok!(EncointerCeremonies::register_participant(Origin::signed(ferdie.clone())));
        assert_eq!(EncointerCeremonies::participant_count(), 3);
        //assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        assert_ok!(EncointerCeremonies::assign_meetups());
        assert_eq!(EncointerCeremonies::meetup_count(), 1);
        let meetup = EncointerCeremonies::meetup_registry(&cindex, &SINGLE_MEETUP_INDEX);
        assert_eq!(meetup.len(), 3);
        assert!(meetup.contains(&alice));
        assert!(meetup.contains(&bob));
        assert!(meetup.contains(&ferdie));

        assert_eq!(EncointerCeremonies::meetup_index(&cindex, &alice), SINGLE_MEETUP_INDEX);
        assert_eq!(EncointerCeremonies::meetup_index(&cindex, &bob), SINGLE_MEETUP_INDEX);
        assert_eq!(EncointerCeremonies::meetup_index(&cindex, &ferdie), SINGLE_MEETUP_INDEX);

    });
}
#[test]
fn assigning_meetup_at_phase_change_and_purge_works() {
    ExtBuilder::build().execute_with(|| {
        let master = AccountId::from(AccountKeyring::Alice);
        let alice = AccountId::from(AccountKeyring::Alice);
        let cindex = EncointerCeremonies::current_ceremony_index();
        assert_ok!(EncointerCeremonies::register_participant(Origin::signed(alice.clone())));
        assert_eq!(EncointerCeremonies::meetup_index(&cindex, &alice), NONE);
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        assert_eq!(EncointerCeremonies::meetup_index(&cindex, &alice), SINGLE_MEETUP_INDEX);
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        assert_eq!(EncointerCeremonies::meetup_index(&cindex, &alice), NONE);
    });
}

#[test]
fn verify_witness_signatue_works() {
    ExtBuilder::build().execute_with(|| {
        // claimant			
        let claimant = AccountKeyring::Alice;
        // witness
        let witness = AccountKeyring::Bob;

        let claim = ClaimOfAttendance {
            claimant_public: get_accountid(claimant),
            ceremony_index: 1,
            meetup_index: SINGLE_MEETUP_INDEX,
            number_of_participants_confirmed: 3,
        };
        let witness_good = TestWitness { 
            claim: claim.clone(),
            signature: Signature::from(witness.sign(&claim.encode())),
            public: get_accountid(witness),
        };
        let witness_wrong_signature = TestWitness { 
            claim: claim.clone(),
            signature: Signature::from(claimant.sign(&claim.encode())),
            public: get_accountid(witness),
        };
        let witness_wrong_signer = TestWitness { 
            claim: claim.clone(),
            signature: Signature::from(witness.sign(&claim.encode())),
            public: get_accountid(claimant),
        };
        assert_ok!(EncointerCeremonies::verify_witness_signature(witness_good));
        assert!(EncointerCeremonies::verify_witness_signature(witness_wrong_signature).is_err());
        assert!(EncointerCeremonies::verify_witness_signature(witness_wrong_signer).is_err());
    });
}

#[test]
fn register_witnesses_works() {
    ExtBuilder::build().execute_with(|| {
        let master = AccountId::from(AccountKeyring::Alice);
        let alice = AccountKeyring::Alice;
        let bob = AccountKeyring::Bob;
        let ferdie = AccountKeyring::Ferdie;
        let cindex = EncointerCeremonies::current_ceremony_index();
        register_alice_bob_ferdie();
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        // WITNESSING
        assert_eq!(EncointerCeremonies::meetup_index(&cindex, &get_accountid(alice)), SINGLE_MEETUP_INDEX);

        gets_witnessed_by(get_accountid(alice), vec!(bob,ferdie),3);
        gets_witnessed_by(get_accountid(bob), vec!(alice,ferdie),3);

        assert_eq!(EncointerCeremonies::witness_count(), 2);
        assert_eq!(EncointerCeremonies::witness_index(&cindex, &get_accountid(bob)), 2);
        let wit_vec = EncointerCeremonies::witness_registry(&cindex, &2);
        assert!(wit_vec.len() == 2);
        assert!(wit_vec.contains(&get_accountid(alice)));
        assert!(wit_vec.contains(&get_accountid(ferdie)));

        // TEST: re-registering must overwrite previous entry
        gets_witnessed_by(get_accountid(alice), vec!(bob,ferdie),3);
        assert_eq!(EncointerCeremonies::witness_count(), 2);	
    });
}

#[test]
fn register_witnesses_for_non_participant_fails_silently() {
    ExtBuilder::build().execute_with(|| {
        let master = AccountId::from(AccountKeyring::Alice);
        let alice = AccountKeyring::Alice;
        let bob = AccountKeyring::Bob;
        let cindex = EncointerCeremonies::current_ceremony_index();
        register_alice_bob_ferdie();
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        // WITNESSING
        gets_witnessed_by(get_accountid(alice), vec!(bob,alice),3);
        assert_eq!(EncointerCeremonies::witness_count(), 1);	
        let wit_vec = EncointerCeremonies::witness_registry(&cindex, &1);
        assert!(wit_vec.contains(&get_accountid(alice)) == false);
        assert!(wit_vec.len() == 1);

    });
}

#[test]
fn register_witnesses_for_non_participant_fails() {
    ExtBuilder::build().execute_with(|| {
        let master = AccountId::from(AccountKeyring::Alice);
        let alice = AccountKeyring::Alice;
        let ferdie = AccountKeyring::Ferdie;
        let eve = AccountKeyring::Eve;
        let cindex = EncointerCeremonies::current_ceremony_index();
        register_alice_bob_ferdie();
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        // WITNESSING
        let mut eve_witnesses: Vec<TestWitness> = vec!();
        eve_witnesses.insert(0, meetup_claim_sign(get_accountid(eve), alice.clone(),3));
        eve_witnesses.insert(1, meetup_claim_sign(get_accountid(eve), ferdie.clone(),3));
        assert!(EncointerCeremonies::register_witnesses(
            Origin::signed(get_accountid(eve)),
            eve_witnesses.clone())
            .is_err());

    });
}

#[test]
fn register_witnesses_with_non_participant_fails_silently() {
    ExtBuilder::build().execute_with(|| {
        let master = AccountId::from(AccountKeyring::Alice);
        let alice = AccountKeyring::Alice;
        let bob = AccountKeyring::Bob;
        let eve = AccountKeyring::Eve;
        let cindex = EncointerCeremonies::current_ceremony_index();
        register_alice_bob_ferdie();
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        // WITNESSING
        gets_witnessed_by(get_accountid(alice), vec!(bob, eve), 3);
        assert_eq!(EncointerCeremonies::witness_count(), 1);	
        let wit_vec = EncointerCeremonies::witness_registry(&cindex, &1);
        assert!(wit_vec.contains(&get_accountid(eve)) == false);
        assert!(wit_vec.len() == 1);			
    });
}

#[test]
fn register_witnesses_with_wrong_meetup_index_fails() {
    ExtBuilder::build().execute_with(|| {
        let master = AccountId::from(AccountKeyring::Alice);
        let alice = AccountKeyring::Alice;
        let bob = AccountKeyring::Bob;
        let ferdie = AccountKeyring::Ferdie;
        let cindex = EncointerCeremonies::current_ceremony_index();
        register_alice_bob_ferdie();
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        // WITNESSING
        let mut alice_witnesses: Vec<TestWitness> = vec!();
        alice_witnesses.insert(0, meetup_claim_sign(get_accountid(alice), bob.clone(), 3));
        let claim = ClaimOfAttendance {
            claimant_public: get_accountid(alice),
            ceremony_index: 1,
            // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            meetup_index: SINGLE_MEETUP_INDEX + 99,
            number_of_participants_confirmed: 3,
        };
        alice_witnesses.insert(1, 
            TestWitness { 
                claim: claim.clone(),
                signature: Signature::from(ferdie.sign(&claim.encode())),
                public: get_accountid(ferdie),
            }
        );
        assert_ok!(EncointerCeremonies::register_witnesses(
            Origin::signed(get_accountid(alice)),
            alice_witnesses));
        let wit_vec = EncointerCeremonies::witness_registry(&cindex, &1);
        assert!(wit_vec.contains(&get_accountid(ferdie)) == false);
        assert!(wit_vec.len() == 1);			
    });
}

#[test]
fn register_witnesses_with_wrong_ceremony_index_fails() {
    ExtBuilder::build().execute_with(|| {
        let master = AccountId::from(AccountKeyring::Alice);
        let alice = AccountKeyring::Alice;
        let bob = AccountKeyring::Bob;
        let ferdie = AccountKeyring::Ferdie;
        let cindex = EncointerCeremonies::current_ceremony_index();
        register_alice_bob_ferdie();
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        // WITNESSING
        let mut alice_witnesses: Vec<TestWitness> = vec!();
        alice_witnesses.insert(0, meetup_claim_sign(get_accountid(alice), bob.clone(), 3));
        let claim = ClaimOfAttendance {
            claimant_public: get_accountid(alice),
            // !!!!!!!!!!!!!!!!!!!!!!!!!!
            ceremony_index: 99,
            meetup_index: SINGLE_MEETUP_INDEX,
            number_of_participants_confirmed: 3,
        };
        alice_witnesses.insert(1, 
            TestWitness { 
                claim: claim.clone(),
                signature: Signature::from(ferdie.sign(&claim.encode())),
                public: get_accountid(ferdie),
            }
        );
        assert_ok!(EncointerCeremonies::register_witnesses(
            Origin::signed(get_accountid(alice)),
            alice_witnesses));
        let wit_vec = EncointerCeremonies::witness_registry(&cindex, &1);
        assert!(wit_vec.contains(&get_accountid(ferdie)) == false);
        assert!(wit_vec.len() == 1);			
    });
}


#[test]
fn ballot_meetup_n_votes_works() {
    ExtBuilder::build().execute_with(|| {
        let master = AccountId::from(AccountKeyring::Alice);
        let alice = AccountKeyring::Alice;
        let bob = AccountKeyring::Bob;
        let ferdie = AccountKeyring::Ferdie;
        let charlie = AccountKeyring::Charlie;
        let dave = AccountKeyring::Dave;
        let eve = AccountKeyring::Eve;
        let cindex = EncointerCeremonies::current_ceremony_index();			
        register_alice_bob_ferdie();
        register_charlie_dave_eve();

        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        // ASSIGNING
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        // WITNESSING
        gets_witnessed_by(get_accountid(alice), vec!(bob),5);
        gets_witnessed_by(get_accountid(bob), vec!(alice),5);
        gets_witnessed_by(get_accountid(charlie), vec!(alice),5);
        gets_witnessed_by(get_accountid(dave), vec!(alice),5);
        gets_witnessed_by(get_accountid(eve), vec!(alice),5);
        gets_witnessed_by(get_accountid(ferdie), vec!(dave),6);
        assert!(EncointerCeremonies::ballot_meetup_n_votes(SINGLE_MEETUP_INDEX) == Some((5,5)));

        gets_witnessed_by(get_accountid(alice), vec!(bob),5);
        gets_witnessed_by(get_accountid(bob), vec!(alice),5);
        gets_witnessed_by(get_accountid(charlie), vec!(alice),4);
        gets_witnessed_by(get_accountid(dave), vec!(alice),4);
        gets_witnessed_by(get_accountid(eve), vec!(alice),6);
        gets_witnessed_by(get_accountid(ferdie), vec!(dave),6);
        assert!(EncointerCeremonies::ballot_meetup_n_votes(SINGLE_MEETUP_INDEX) == None);

        gets_witnessed_by(get_accountid(alice), vec!(bob),5);
        gets_witnessed_by(get_accountid(bob), vec!(alice),5);
        gets_witnessed_by(get_accountid(charlie), vec!(alice),5);
        gets_witnessed_by(get_accountid(dave), vec!(alice),4);
        gets_witnessed_by(get_accountid(eve), vec!(alice),6);
        gets_witnessed_by(get_accountid(ferdie), vec!(dave),6);
        assert!(EncointerCeremonies::ballot_meetup_n_votes(SINGLE_MEETUP_INDEX) == Some((5,3)));
    });
}

#[test]
fn issue_reward_works() {
    ExtBuilder::build().execute_with(|| {
        let master = AccountId::from(AccountKeyring::Alice);
        let alice = AccountKeyring::Alice;
        let bob = AccountKeyring::Bob;
        let ferdie = AccountKeyring::Ferdie;
        let charlie = AccountKeyring::Charlie;
        let dave = AccountKeyring::Dave;
        let eve = AccountKeyring::Eve;
        let cindex = EncointerCeremonies::current_ceremony_index();			
        register_alice_bob_ferdie();
        register_charlie_dave_eve();

        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        // ASSIGNING
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        // WITNESSING
        // ferdi doesn't show up
        // eve signs no one else
        // charlie collects incomplete signatures
        // dave signs ferdi and reports wrong number of participants
        gets_witnessed_by(get_accountid(alice), vec!(bob,charlie,dave),5);
        gets_witnessed_by(get_accountid(bob), vec!(alice,charlie,dave),5);
        gets_witnessed_by(get_accountid(charlie), vec!(alice,bob),5);
        gets_witnessed_by(get_accountid(dave), vec!(alice,bob,charlie),6);
        gets_witnessed_by(get_accountid(eve), vec!(alice,bob,charlie,dave),5);
        gets_witnessed_by(get_accountid(ferdie), vec!(dave),6);
        assert_eq!(Balances::free_balance(&get_accountid(alice)), 0);

        assert_ok!(EncointerCeremonies::issue_rewards());

        assert_eq!(Balances::free_balance(&get_accountid(alice)), REWARD);
        assert_eq!(Balances::free_balance(&get_accountid(bob)), REWARD);
        assert_eq!(Balances::free_balance(&get_accountid(charlie)), 0);
        assert_eq!(Balances::free_balance(&get_accountid(eve)), 0);
        assert_eq!(Balances::free_balance(&get_accountid(ferdie)), 0);
    });
}

