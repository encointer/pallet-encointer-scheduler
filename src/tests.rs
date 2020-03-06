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
use encointer_currencies::{Location, CurrencyIdentifier};

const NONE: u64 = 0;
const REWARD: Balance = 1000;

thread_local! {
    static EXISTENTIAL_DEPOSIT: RefCell<u64> = RefCell::new(0);
}
pub type BlockNumber = u64;
pub type Balance = u64;

type TestAttestation = Attestation<Signature, AccountId>;
type TestProofOfAttendance = ProofOfAttendance<Signature, AccountId>;

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

impl encointer_currencies::Trait for TestRuntime {
    type Event = ();
}

pub type EncointerCurrencies = encointer_currencies::Module<TestRuntime>;

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
        encointer_currencies::GenesisConfig::<TestRuntime> {
            currency_master: AccountId::from(AccountKeyring::Alice),
        }.assimilate_storage(&mut storage).unwrap();	
        GenesisConfig::<TestRuntime> {
            current_ceremony_index: 1,
            ceremony_reward: REWARD,
            ceremony_master: AccountId::from(AccountKeyring::Alice),
        }.assimilate_storage(&mut storage).unwrap();		
        runtime_io::TestExternalities::from(storage)
    }
}

impl_outer_origin!{
    pub enum Origin for TestRuntime {}
}

fn meetup_claim_sign(claimant: AccountId, attester: sr25519::Pair, 
    cid: CurrencyIdentifier, cindex: CeremonyIndexType, mindex: MeetupIndexType, n_participants: u32) -> TestAttestation 
{
    let claim = ClaimOfAttendance {
        claimant_public: claimant.clone(),
        currency_identifier: cid,
        ceremony_index: cindex,
        meetup_index: mindex,
        number_of_participants_confirmed: n_participants,
    };
    TestAttestation { 
        claim: claim.clone(),
        signature: Signature::from(attester.sign(&claim.encode())),
        public: get_accountid(&attester),
    }
}

fn prove_attendance(prover: AccountId, cid: CurrencyIdentifier, cindex: CeremonyIndexType, attendee: &sr25519::Pair) -> TestProofOfAttendance {
    let msg = (prover.clone(), cindex);
    ProofOfAttendance{
        prover_public: prover,
        currency_identifier: cid,
        ceremony_index: cindex,
        attendee_public: get_accountid(&attendee),
        attendee_signature: Signature::from(attendee.sign(&msg.encode())),
    }
}

fn register_alice_bob_ferdie(cid: CurrencyIdentifier) {
    assert_ok!(EncointerCeremonies::register_participant(Origin::signed(get_accountid(&AccountKeyring::Alice.pair())), cid, None));
    assert_ok!(EncointerCeremonies::register_participant(Origin::signed(get_accountid(&AccountKeyring::Bob.pair())), cid, None));
    assert_ok!(EncointerCeremonies::register_participant(Origin::signed(get_accountid(&AccountKeyring::Ferdie.pair())), cid, None));
}

fn register_charlie_dave_eve(cid: CurrencyIdentifier) {
    assert_ok!(EncointerCeremonies::register_participant(Origin::signed(get_accountid(&AccountKeyring::Charlie.pair())), cid, None));
    assert_ok!(EncointerCeremonies::register_participant(Origin::signed(get_accountid(&AccountKeyring::Dave.pair())), cid, None));
    assert_ok!(EncointerCeremonies::register_participant(Origin::signed(get_accountid(&AccountKeyring::Eve.pair())), cid, None));
}

fn gets_attested_by(claimant: AccountId, attestations: Vec<&sr25519::Pair>, 
    cid: CurrencyIdentifier, cindex: CeremonyIndexType, mindex: MeetupIndexType, n_participants: u32) {
    let mut testimonials: Vec<TestAttestation> = vec!();
    for a in attestations {
        testimonials.insert(0, 
            meetup_claim_sign(claimant.clone(), a.clone(), cid, cindex, mindex, n_participants));
        
    }
    assert_ok!(EncointerCeremonies::register_attestations(
            Origin::signed(claimant),
            testimonials.clone()));	
}

fn get_accountid(pair: &sr25519::Pair) -> AccountId {
    AccountPublic::from(pair.public()).into_account()
}

fn register_test_currency() -> CurrencyIdentifier {
    // all well-known keys are boottrappers for easy testen afterwards
    let alice = AccountId::from(AccountKeyring::Alice);
    let bob = AccountId::from(AccountKeyring::Bob);
    let charlie = AccountId::from(AccountKeyring::Charlie);
    let dave = AccountId::from(AccountKeyring::Dave);
    let eve = AccountId::from(AccountKeyring::Eve);
    let ferdie = AccountId::from(AccountKeyring::Ferdie);
    let a = Location {lat: 1_000_000, lon: 1_000_000 };
    let b = Location {lat: 1_000_000, lon: 2_000_000 };
    let c = Location {lat: 1_000_000, lon: 3_000_000 };
    let loc = vec!(a,b,c);
    let bs = vec!(alice.clone(), bob.clone(), charlie.clone(), dave.clone(), eve.clone(), ferdie.clone());
    let cid = CurrencyIdentifier::default();
    assert_ok!(EncointerCurrencies::new_currency(Origin::signed(alice.clone()), cid, loc, bs));
    cid
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
        assert_eq!(EncointerCeremonies::current_phase(), CeremonyPhaseType::ATTESTING);
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        assert_eq!(EncointerCeremonies::current_phase(), CeremonyPhaseType::REGISTERING);
        assert_eq!(EncointerCeremonies::current_ceremony_index(), 2);						
    });
}

#[test]
fn registering_participant_works() {
    ExtBuilder::build().execute_with(|| {
        let cid = register_test_currency();
        let alice = AccountId::from(AccountKeyring::Alice);
        let bob = AccountId::from(AccountKeyring::Bob);
        let cindex = EncointerCeremonies::current_ceremony_index();
        assert_eq!(EncointerCeremonies::participant_count((cid, cindex)), 0);
        assert_ok!(EncointerCeremonies::register_participant(Origin::signed(alice.clone()), cid, None));
        assert_eq!(EncointerCeremonies::participant_count((cid, cindex)), 1);
        assert_ok!(EncointerCeremonies::register_participant(Origin::signed(bob.clone()), cid, None));
        assert_eq!(EncointerCeremonies::participant_count((cid, cindex)), 2);
        assert_eq!(EncointerCeremonies::participant_index((cid, cindex), &bob), 2);
        assert_eq!(EncointerCeremonies::participant_registry((cid, cindex), &1), alice);
        assert_eq!(EncointerCeremonies::participant_registry((cid, cindex), &2), bob);
    });
}

#[test]
fn registering_participant_twice_fails() {
    ExtBuilder::build().execute_with(|| {
        let cid = register_test_currency();
        let alice = AccountId::from(AccountKeyring::Alice);
        assert_ok!(EncointerCeremonies::register_participant(Origin::signed(alice.clone()), cid, None));
        assert!(EncointerCeremonies::register_participant(Origin::signed(alice.clone()), cid, None).is_err());
    });
}

#[test]
fn ceremony_index_and_purging_registry_works() {
    ExtBuilder::build().execute_with(|| {
        let cid = register_test_currency();
        let master = AccountId::from(AccountKeyring::Alice);
        let alice = AccountId::from(AccountKeyring::Alice);
        let cindex = EncointerCeremonies::current_ceremony_index();
        assert_ok!(EncointerCeremonies::register_participant(Origin::signed(alice.clone()), cid, None));
        assert_eq!(EncointerCeremonies::participant_registry((cid, cindex), &1), alice);
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        // now assigning
        assert_eq!(EncointerCeremonies::participant_registry((cid, cindex), &1), alice);
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        // now attesting
        assert_eq!(EncointerCeremonies::participant_registry((cid, cindex), &1), alice);
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        // now again registering
        let new_cindex = EncointerCeremonies::current_ceremony_index();
        assert_eq!(new_cindex, cindex+1);
        assert_eq!(EncointerCeremonies::participant_count((cid, cindex)), 0);
        assert_eq!(EncointerCeremonies::participant_registry((cid, cindex), &1), AccountId::default());
        assert_eq!(EncointerCeremonies::participant_index((cid, cindex), &alice), NONE);
    });
}

#[test]
fn registering_participant_in_wrong_phase_fails() {
    ExtBuilder::build().execute_with(|| {
        let cid = register_test_currency();
        let master = AccountId::from(AccountKeyring::Alice);
        let alice = AccountId::from(AccountKeyring::Alice);
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        assert_eq!(EncointerCeremonies::current_phase(), CeremonyPhaseType::ASSIGNING);
        assert!(EncointerCeremonies::register_participant(Origin::signed(alice.clone()), cid, None).is_err());
    });
}

#[test]
fn assigning_meetup_works() {
    ExtBuilder::build().execute_with(|| {
        let cid = register_test_currency();
        let master = AccountId::from(AccountKeyring::Alice);
        let alice = AccountId::from(AccountKeyring::Alice);
        let bob = AccountId::from(AccountKeyring::Bob);
        let ferdie = AccountId::from(AccountKeyring::Ferdie);
        let cindex = EncointerCeremonies::current_ceremony_index();
        assert_ok!(EncointerCeremonies::register_participant(Origin::signed(alice.clone()), cid, None));
        assert_ok!(EncointerCeremonies::register_participant(Origin::signed(bob.clone()), cid, None));
        assert_ok!(EncointerCeremonies::register_participant(Origin::signed(ferdie.clone()), cid, None));
        assert_eq!(EncointerCeremonies::participant_count((cid, cindex)), 3);
        //assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        assert_ok!(EncointerCeremonies::assign_meetups());
        assert_eq!(EncointerCeremonies::meetup_count((cid, cindex)), 1);
        let meetup = EncointerCeremonies::meetup_registry((cid, cindex), 1);
        assert_eq!(meetup.len(), 3);
        assert!(meetup.contains(&alice));
        assert!(meetup.contains(&bob));
        assert!(meetup.contains(&ferdie));

        assert_eq!(EncointerCeremonies::meetup_index((cid, cindex), &alice), 1);
        assert_eq!(EncointerCeremonies::meetup_index((cid, cindex), &bob), 1);
        assert_eq!(EncointerCeremonies::meetup_index((cid, cindex), &ferdie), 1);

    });
}
#[test]
fn assigning_meetup_at_phase_change_and_purge_works() {
    ExtBuilder::build().execute_with(|| {
        let cid = register_test_currency();
        let master = AccountId::from(AccountKeyring::Alice);
        let alice = AccountId::from(AccountKeyring::Alice);
        let cindex = EncointerCeremonies::current_ceremony_index();
        register_alice_bob_ferdie(cid);
        assert_eq!(EncointerCeremonies::meetup_index((cid, cindex), &alice), NONE);
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        assert_eq!(EncointerCeremonies::meetup_index((cid, cindex), &alice), 1);
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        assert_eq!(EncointerCeremonies::meetup_index((cid, cindex), &alice), NONE);
    });
}

#[test]
fn verify_attestation_signatue_works() {
    ExtBuilder::build().execute_with(|| {
        let cid = register_test_currency();
        let claimant = AccountKeyring::Alice.pair();
        let attester = AccountKeyring::Bob.pair();

        let claim = ClaimOfAttendance {
            claimant_public: get_accountid(&claimant),
            currency_identifier: cid,
            ceremony_index: 1,
            meetup_index: 1,
            number_of_participants_confirmed: 3,
        };
        let attestation_good = TestAttestation { 
            claim: claim.clone(),
            signature: Signature::from(attester.sign(&claim.encode())),
            public: get_accountid(&attester),
        };
        let attestation_wrong_signature = TestAttestation { 
            claim: claim.clone(),
            signature: Signature::from(claimant.sign(&claim.encode())),
            public: get_accountid(&attester),
        };
        let attestation_wrong_signer = TestAttestation { 
            claim: claim.clone(),
            signature: Signature::from(attester.sign(&claim.encode())),
            public: get_accountid(&claimant),
        };
        assert_ok!(EncointerCeremonies::verify_attestation_signature(attestation_good));
        assert!(EncointerCeremonies::verify_attestation_signature(attestation_wrong_signature).is_err());
        assert!(EncointerCeremonies::verify_attestation_signature(attestation_wrong_signer).is_err());
    });
}

#[test]
fn register_attestations_works() {
    ExtBuilder::build().execute_with(|| {
        let cid = register_test_currency();
        let master = AccountId::from(AccountKeyring::Alice);
        let alice = AccountKeyring::Alice.pair();
        let bob = AccountKeyring::Bob.pair();
        let ferdie = AccountKeyring::Ferdie.pair();
        let cindex = EncointerCeremonies::current_ceremony_index();
        register_alice_bob_ferdie(cid);
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        // ATTESTING
        assert_eq!(EncointerCeremonies::meetup_index((cid, cindex), &get_accountid(&alice)), 1);

        gets_attested_by(get_accountid(&alice), vec!(&bob,&ferdie), cid ,1, 1, 3);
        gets_attested_by(get_accountid(&bob), vec!(&alice,&ferdie), cid, 1, 1, 3);

        assert_eq!(EncointerCeremonies::attestation_count((cid, cindex)), 2);
        assert_eq!(EncointerCeremonies::attestation_index((cid, cindex), &get_accountid(&bob)), 2);
        let wit_vec = EncointerCeremonies::attestation_registry((cid, cindex), &2);
        assert!(wit_vec.len() == 2);
        assert!(wit_vec.contains(&get_accountid(&alice)));
        assert!(wit_vec.contains(&get_accountid(&ferdie)));

        // TEST: re-registering must overwrite previous entry
        gets_attested_by(get_accountid(&alice), vec!(&bob,&ferdie), cid, 1, 1, 3);
        assert_eq!(EncointerCeremonies::attestation_count((cid, cindex)), 2);	
    });
}

#[test]
fn register_attestations_for_non_participant_fails_silently() {
    ExtBuilder::build().execute_with(|| {
        let cid = register_test_currency();
        let master = AccountId::from(AccountKeyring::Alice);
        let alice = AccountKeyring::Alice.pair();
        let bob = AccountKeyring::Bob.pair();
        let cindex = EncointerCeremonies::current_ceremony_index();
        register_alice_bob_ferdie(cid);
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        // ATTESTING
        gets_attested_by(get_accountid(&alice), vec!(&bob,&alice), cid, 1, 1, 3);
        assert_eq!(EncointerCeremonies::attestation_count((cid, cindex)), 1);	
        let wit_vec = EncointerCeremonies::attestation_registry((cid, cindex), &1);
        assert!(wit_vec.contains(&get_accountid(&alice)) == false);
        assert!(wit_vec.len() == 1);

    });
}

#[test]
fn register_attestations_for_non_participant_fails() {
    ExtBuilder::build().execute_with(|| {
        let cid = register_test_currency();
        let master = AccountId::from(AccountKeyring::Alice);
        let alice = AccountKeyring::Alice.pair();
        let ferdie = AccountKeyring::Ferdie.pair();
        let eve = AccountKeyring::Eve.pair();
        let cindex = EncointerCeremonies::current_ceremony_index();
        register_alice_bob_ferdie(cid);
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        // ATTESTING
        let mut eve_attestations: Vec<TestAttestation> = vec!();
        eve_attestations.insert(0, meetup_claim_sign(get_accountid(&eve), alice.clone(), cid, 1, 1, 3));
        eve_attestations.insert(1, meetup_claim_sign(get_accountid(&eve), ferdie.clone(), cid, 1, 1, 3));
        assert!(EncointerCeremonies::register_attestations(
            Origin::signed(get_accountid(&eve)),
            eve_attestations.clone())
            .is_err());

    });
}

#[test]
fn register_attestations_with_non_participant_fails_silently() {
    ExtBuilder::build().execute_with(|| {
        let cid = register_test_currency();
        let master = AccountId::from(AccountKeyring::Alice);
        let alice = AccountKeyring::Alice.pair();
        let bob = AccountKeyring::Bob.pair();
        let eve = AccountKeyring::Eve.pair();
        let cindex = EncointerCeremonies::current_ceremony_index();
        register_alice_bob_ferdie(cid);
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        // ATTESTING
        gets_attested_by(get_accountid(&alice), vec!(&bob, &eve), cid, 1, 1, 3);
        assert_eq!(EncointerCeremonies::attestation_count((cid, cindex)), 1);	
        let wit_vec = EncointerCeremonies::attestation_registry((cid, cindex), &1);
        assert!(wit_vec.contains(&get_accountid(&eve)) == false);
        assert!(wit_vec.len() == 1);			
    });
}

#[test]
fn register_attestations_with_wrong_meetup_index_fails() {
    ExtBuilder::build().execute_with(|| {
        let cid = register_test_currency();
        let master = AccountId::from(AccountKeyring::Alice);
        let alice = AccountKeyring::Alice.pair();
        let bob = AccountKeyring::Bob.pair();
        let ferdie = AccountKeyring::Ferdie.pair();
        let cindex = EncointerCeremonies::current_ceremony_index();
        register_alice_bob_ferdie(cid);
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        // ATTESTING
        let mut alice_attestations: Vec<TestAttestation> = vec!();
        alice_attestations.insert(0, meetup_claim_sign(get_accountid(&alice), bob.clone(), cid, 1, 1, 3));
        let claim = ClaimOfAttendance {
            claimant_public: get_accountid(&alice),
            currency_identifier: cid,
            ceremony_index: 1,
            // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            meetup_index: 1 + 99,
            number_of_participants_confirmed: 3,
        };
        alice_attestations.insert(1, 
            TestAttestation { 
                claim: claim.clone(),
                signature: Signature::from(ferdie.sign(&claim.encode())),
                public: get_accountid(&ferdie),
            }
        );
        assert_ok!(EncointerCeremonies::register_attestations(
            Origin::signed(get_accountid(&alice)),
            alice_attestations));
        let wit_vec = EncointerCeremonies::attestation_registry((cid, cindex), &1);
        assert!(wit_vec.contains(&get_accountid(&ferdie)) == false);
        assert!(wit_vec.len() == 1);			
    });
}

#[test]
fn register_attestations_with_wrong_ceremony_index_fails() {
    ExtBuilder::build().execute_with(|| {
        let cid = register_test_currency();
        let master = AccountId::from(AccountKeyring::Alice);
        let alice = AccountKeyring::Alice.pair();
        let bob = AccountKeyring::Bob.pair();
        let ferdie = AccountKeyring::Ferdie.pair();
        let cindex = EncointerCeremonies::current_ceremony_index();
        register_alice_bob_ferdie(cid);
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        // ATTESTING
        let mut alice_attestations: Vec<TestAttestation> = vec!();
        alice_attestations.insert(0, meetup_claim_sign(get_accountid(&alice), bob.clone(), cid, 1, 1, 3));
        let claim = ClaimOfAttendance {
            claimant_public: get_accountid(&alice),
            currency_identifier: cid,
            // !!!!!!!!!!!!!!!!!!!!!!!!!!
            ceremony_index: 99,
            meetup_index: 1,
            number_of_participants_confirmed: 3,
        };
        alice_attestations.insert(1, 
            TestAttestation { 
                claim: claim.clone(),
                signature: Signature::from(ferdie.sign(&claim.encode())),
                public: get_accountid(&ferdie),
            }
        );
        assert_ok!(EncointerCeremonies::register_attestations(
            Origin::signed(get_accountid(&alice)),
            alice_attestations));
        let wit_vec = EncointerCeremonies::attestation_registry((cid, cindex), &1);
        assert!(wit_vec.contains(&get_accountid(&ferdie)) == false);
        assert!(wit_vec.len() == 1);			
    });
}


#[test]
fn ballot_meetup_n_votes_works() {
    ExtBuilder::build().execute_with(|| {
        let cid = register_test_currency();
        let master = AccountId::from(AccountKeyring::Alice);
        let alice = AccountKeyring::Alice.pair();
        let bob = AccountKeyring::Bob.pair();
        let ferdie = AccountKeyring::Ferdie.pair();
        let charlie = AccountKeyring::Charlie.pair();
        let dave = AccountKeyring::Dave.pair();
        let eve = AccountKeyring::Eve.pair();
        let cindex = EncointerCeremonies::current_ceremony_index();			
        register_alice_bob_ferdie(cid);
        register_charlie_dave_eve(cid);

        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        // ASSIGNING
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        // ATTESTING
        gets_attested_by(get_accountid(&alice), vec!(&bob), cid, 1, 1, 5);
        gets_attested_by(get_accountid(&bob), vec!(&alice), cid, 1, 1, 5);
        gets_attested_by(get_accountid(&charlie), vec!(&alice), cid, 1, 1, 5);
        gets_attested_by(get_accountid(&dave), vec!(&alice), cid, 1, 1, 5);
        gets_attested_by(get_accountid(&eve), vec!(&alice), cid, 1, 1, 5);
        gets_attested_by(get_accountid(&ferdie), vec!(&dave), cid, 1, 1, 6);
        assert!(EncointerCeremonies::ballot_meetup_n_votes(&cid, 1) == Some((5,5)));

        gets_attested_by(get_accountid(&alice), vec!(&bob), cid, 1, 1, 5);
        gets_attested_by(get_accountid(&bob), vec!(&alice), cid, 1, 1, 5);
        gets_attested_by(get_accountid(&charlie), vec!(&alice), cid, 1, 1, 4);
        gets_attested_by(get_accountid(&dave), vec!(&alice), cid, 1, 1, 4);
        gets_attested_by(get_accountid(&eve), vec!(&alice), cid, 1, 1, 6);
        gets_attested_by(get_accountid(&ferdie), vec!(&dave), cid, 1, 1, 6);
        assert!(EncointerCeremonies::ballot_meetup_n_votes(&cid, 1) == None);

        gets_attested_by(get_accountid(&alice), vec!(&bob), cid, 1, 1, 5);
        gets_attested_by(get_accountid(&bob), vec!(&alice), cid, 1, 1, 5);
        gets_attested_by(get_accountid(&charlie), vec!(&alice), cid, 1, 1, 5);
        gets_attested_by(get_accountid(&dave), vec!(&alice), cid, 1, 1, 4);
        gets_attested_by(get_accountid(&eve), vec!(&alice), cid, 1, 1, 6);
        gets_attested_by(get_accountid(&ferdie), vec!(&dave), cid, 1, 1, 6);
        assert!(EncointerCeremonies::ballot_meetup_n_votes(&cid, 1) == Some((5,3)));
    });
}

#[test]
fn issue_reward_works() {
    ExtBuilder::build().execute_with(|| {
        let cid = register_test_currency();
        let master = AccountId::from(AccountKeyring::Alice);
        let alice = AccountKeyring::Alice.pair();
        let bob = AccountKeyring::Bob.pair();
        let ferdie = AccountKeyring::Ferdie.pair();
        let charlie = AccountKeyring::Charlie.pair();
        let dave = AccountKeyring::Dave.pair();
        let eve = AccountKeyring::Eve.pair();
        let cindex = EncointerCeremonies::current_ceremony_index();			
        register_alice_bob_ferdie(cid);
        register_charlie_dave_eve(cid);

        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        // ASSIGNING
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        // ATTESTING
        // ferdi doesn't show up
        // eve signs no one else
        // charlie collects incomplete signatures
        // dave signs ferdi and reports wrong number of participants
        gets_attested_by(get_accountid(&alice), vec!(&bob,&charlie,&dave), cid, 1, 1, 5);
        gets_attested_by(get_accountid(&bob), vec!(&alice,&charlie,&dave), cid, 1, 1, 5);
        gets_attested_by(get_accountid(&charlie), vec!(&alice,&bob), cid, 1, 1, 5);
        gets_attested_by(get_accountid(&dave), vec!(&alice,&bob,&charlie), cid, 1, 1, 6);
        gets_attested_by(get_accountid(&eve), vec!(&alice,&bob,&charlie,&dave), cid, 1, 1, 5);
        gets_attested_by(get_accountid(&ferdie), vec!(&dave), cid, 1, 1, 6);
        assert_eq!(Balances::free_balance(&get_accountid(&alice)), 0);
        
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        // REGISTERING

        assert_eq!(Balances::free_balance(&get_accountid(&alice)), REWARD);
        assert_eq!(Balances::free_balance(&get_accountid(&bob)), REWARD);
        assert_eq!(Balances::free_balance(&get_accountid(&charlie)), 0);
        assert_eq!(Balances::free_balance(&get_accountid(&eve)), 0);
        assert_eq!(Balances::free_balance(&get_accountid(&ferdie)), 0);

        assert_eq!(EncointerCeremonies::participant_reputation((cid, cindex), &get_accountid(&alice)), Reputation::VERIFIED_UNLINKED);
        assert_eq!(EncointerCeremonies::participant_reputation((cid, cindex), &get_accountid(&bob)), Reputation::VERIFIED_UNLINKED);
        assert_eq!(EncointerCeremonies::participant_reputation((cid, cindex), &get_accountid(&charlie)), Reputation::UNVERIFIED);
        assert_eq!(EncointerCeremonies::participant_reputation((cid, cindex), &get_accountid(&eve)), Reputation::UNVERIFIED);
        assert_eq!(EncointerCeremonies::participant_reputation((cid, cindex), &get_accountid(&ferdie)), Reputation::UNVERIFIED);
        
    });
}

#[test]
fn register_with_reputation_works() {
    ExtBuilder::build().execute_with(|| {
        let cid = register_test_currency();
        let master = AccountId::from(AccountKeyring::Alice);
        let alice = AccountKeyring::Alice.pair();
        let alice_new = AccountKeyring::Bob.pair();
        let charlie = AccountKeyring::Charlie.pair();
        let cindex = EncointerCeremonies::current_ceremony_index();			

        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        
        // fake reputation registry for first ceremony
        <Module<TestRuntime> as encointer_currencies::Trait>::ParticipantReputation::insert((cid, 1), 
            &get_accountid(&alice), Reputation::VERIFIED_UNLINKED);
//        EncointerCeremonies::register_verified_attendee(cindex, &get_accountid(&alice));
//        assert!(EncointerCeremonies::participant_reputation((cid, 1), &get_accountid(&alice)) == Reputation::VERIFIED_UNLINKED);

        let cindex = EncointerCeremonies::current_ceremony_index();
        println!("cindex {}", cindex);
        // wrong sender of good proof fails
        let proof = prove_attendance(get_accountid(&alice_new), cid, cindex-1, &alice);
        assert!(EncointerCeremonies::register_participant(Origin::signed(get_accountid(&charlie)), cid, Some(proof))
            .is_err());

        // see if Alice can register with her fresh key
        // for the next ceremony claiming her former attendance
        let proof = prove_attendance(get_accountid(&alice_new), cid, cindex-1, &alice);
        assert_ok!(EncointerCeremonies::register_participant(Origin::signed(get_accountid(&alice_new)), cid, Some(proof)));
        assert_eq!(EncointerCeremonies::participant_reputation((cid, cindex), get_accountid(&alice_new)), Reputation::UNVERIFIED_REPUTABLE);
        assert_eq!(EncointerCeremonies::participant_reputation((cid, cindex-1), get_accountid(&alice)), Reputation::VERIFIED_LINKED);

        // double signing (re-using reputation) fails
        let proof_second = prove_attendance(get_accountid(&charlie), cid, cindex-1, &alice);
        assert!(EncointerCeremonies::register_participant(Origin::signed(get_accountid(&charlie)), cid, Some(proof_second))
            .is_err());

        // signer without reputation fails
        let proof = prove_attendance(get_accountid(&charlie), cid, cindex-1, &charlie);
        assert!(EncointerCeremonies::register_participant(Origin::signed(get_accountid(&charlie)), cid, Some(proof))
            .is_err());
    });
}

/*
#[test]
fn test_random_permutation_works() {
    ExtBuilder::build().execute_with(|| {
        let ordered = vec!(1u8, 2, 3, 4, 5, 6);
        let permutation = EncointerCeremonies::random_permutation(ordered);
        println!("random permutation result {}", permutation);
    });
}
*/

#[test]
fn assign_multiple_meetups_works() {
    ExtBuilder::build().execute_with(|| {
        let cid = register_test_currency();
        let master = AccountId::from(AccountKeyring::Alice);
        let mut participants = Vec::<sr25519::Pair>::with_capacity(64);
        // generate many keys and register all of them
        for i in 0u8..13 {
            let mut entropy = [0u8; 32];
            entropy[0] = i;
            let pair = sr25519::Pair::from_entropy(&entropy, None).0;
            participants.push(pair.clone());
            EncointerCeremonies::register_participant(Origin::signed(get_accountid(&pair)), cid, None);
        }
        let cindex = EncointerCeremonies::current_ceremony_index();	
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));

        assert_eq!(EncointerCeremonies::meetup_count((cid, cindex)), 2);
        let meetup1_1 = EncointerCeremonies::meetup_registry((cid, cindex), 1);
        let meetup1_2 = EncointerCeremonies::meetup_registry((cid, cindex), 2);
        println!("ceremony 1 meetup 1 {:?}", meetup1_1);
        
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));        
        assert_eq!(EncointerCeremonies::current_phase(), CeremonyPhaseType::REGISTERING); 


        // new participants without reputation want to join
        for i in 13u8..26 {
            let mut entropy = [0u8; 32];
            entropy[0] = i;
            let pair = sr25519::Pair::from_entropy(&entropy, None).0;
            participants.push(pair.clone());
        }
        //register everyone
        for p in participants.iter() {
            EncointerCeremonies::register_participant(Origin::signed(get_accountid(&p)), cid, None);
        }
        assert_ok!(EncointerCeremonies::next_phase(Origin::signed(master.clone())));

        //verify meetup assignment rules....

        // whitepaper III-B Rule 1: minimize the number of participants that have met at previous ceremony
        
        // whitepaper III-B Rule 2: maximize number of participants per meetup within 3<=N<=12 

        // whitepaper III-B Rule 3: no more than 1/4 participants without reputation
    });
}

#[test]
fn bootstrapping_works() {
    ExtBuilder::build().execute_with(|| {
        let cid = register_test_currency();
        let master = AccountId::from(AccountKeyring::Alice);
        let alice = AccountKeyring::Alice.pair();
        let bob = AccountKeyring::Bob.pair();
        let ferdie = AccountKeyring::Ferdie.pair();

        // no one but the bootstrappers can start a currency


    });
}