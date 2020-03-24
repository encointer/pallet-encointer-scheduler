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

use crate::{Module, Trait, CeremonyPhaseType, GenesisConfig};
use sr_primitives::{
	testing::Header,
	traits::{BlakeTwo256, IdentityLookup},
	Perbill,
};
use primitives::H256;
use support::{assert_ok, impl_outer_origin, impl_outer_event, parameter_types};
use runtime_io::TestExternalities;

impl_outer_origin! {
	pub enum Origin for TestRuntime {}
}

mod simple_event {
	pub use crate::Event;
}

impl_outer_event! {
	pub enum TestEvent for TestRuntime {
		simple_event,
		//system<T>,
	}
}

parameter_types! {
	pub const MomentsPerDay: u64 = 86_400_000; // [ms/d]
}
impl Trait for TestRuntime {
    type Event = TestEvent;
    type OnCeremonyPhaseChange = ();
    type MomentsPerDay = MomentsPerDay;
}

type AccountId = u64;

// Workaround for https://github.com/rust-lang/rust/issues/26925 . Remove when sorted.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TestRuntime;

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
	type BlockNumber = u64;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = AccountId;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Header = Header;
	type Event = TestEvent;
	type BlockHashCount = BlockHashCount;
	type MaximumBlockWeight = MaximumBlockWeight;
	type MaximumBlockLength = MaximumBlockLength;
	type AvailableBlockRatio = AvailableBlockRatio;
	type Version = ();
}

parameter_types! {
    pub const MinimumPeriod: u64 = 1;
}
impl timestamp::Trait for TestRuntime {
	type Moment = u64;
	type OnTimestampSet = EncointerScheduler;
	type MinimumPeriod = MinimumPeriod;
}

pub struct ExtBuilder;

const MASTER: AccountId = 0;

impl ExtBuilder {
    pub fn build() -> TestExternalities {
        let mut storage = system::GenesisConfig::default()
            .build_storage::<TestRuntime>()
            .unwrap();
        GenesisConfig::<TestRuntime> {
            current_ceremony_index: 1,
            ceremony_master: MASTER,
            phase_durations: vec![
                (CeremonyPhaseType::REGISTERING, 86_400_000),
                (CeremonyPhaseType::ASSIGNING, 86_400_000),
                (CeremonyPhaseType::ATTESTING, 86_400_000),
            ]
        }
        .assimilate_storage(&mut storage)
        .unwrap();
        runtime_io::TestExternalities::from(storage)
    }
}

pub type Timestamp = timestamp::Module<TestRuntime>;
pub type EncointerScheduler = Module<TestRuntime>;


#[test]
fn ceremony_phase_statemachine_works() {
    ExtBuilder::build().execute_with(|| {
        assert_eq!(
            EncointerScheduler::current_phase(),
            CeremonyPhaseType::REGISTERING
        );
        assert_eq!(EncointerScheduler::current_ceremony_index(), 1);
        assert_ok!(EncointerScheduler::next_phase(Origin::signed(
            MASTER
        )));
        assert_eq!(
            EncointerScheduler::current_phase(),
            CeremonyPhaseType::ASSIGNING
        );
        assert_ok!(EncointerScheduler::next_phase(Origin::signed(
            MASTER
        )));
        assert_eq!(
            EncointerScheduler::current_phase(),
            CeremonyPhaseType::ATTESTING
        );
        assert_ok!(EncointerScheduler::next_phase(Origin::signed(
            MASTER
        )));
        assert_eq!(
            EncointerScheduler::current_phase(),
            CeremonyPhaseType::REGISTERING
        );
        assert_eq!(EncointerScheduler::current_ceremony_index(), 2);
    });
}

#[test]
fn timestamp_callback_works() {
    ExtBuilder::build().execute_with(|| {
        //large offset since 1970 to when first block is generated
        const GENESIS_TIME: u64 = 1_585_058_843_000;
        const ONE_DAY: u64 = 86_400_000;
        
        Timestamp::set_timestamp(GENESIS_TIME);
        assert_eq!(EncointerScheduler::current_ceremony_index(), 1);
        assert_eq!(
            EncointerScheduler::current_phase(),
            CeremonyPhaseType::REGISTERING
        );
        assert_eq!(EncointerScheduler::next_phase_timestamp(), GENESIS_TIME + ONE_DAY);

        Timestamp::set_timestamp(GENESIS_TIME + ONE_DAY);
        assert_eq!(EncointerScheduler::current_ceremony_index(), 1);
        assert_eq!(
            EncointerScheduler::current_phase(),
            CeremonyPhaseType::ASSIGNING
        );

        Timestamp::set_timestamp(GENESIS_TIME + 2*ONE_DAY);
        assert_eq!(EncointerScheduler::current_ceremony_index(), 1);
        assert_eq!(
            EncointerScheduler::current_phase(),
            CeremonyPhaseType::ATTESTING
        );

        Timestamp::set_timestamp(GENESIS_TIME + 3*ONE_DAY);
        assert_eq!(EncointerScheduler::current_ceremony_index(), 2);
        assert_eq!(
            EncointerScheduler::current_phase(),
            CeremonyPhaseType::REGISTERING
        );

    });
}