pub mod quicmutator;
use std::{ops::RangeBounds, vec::Splice, vec::Drain};

pub use quicmutator::*;

use libafl::inputs::bytes;
pub use bytes::BytesInput;

use libafl::inputs::encoded;
pub use encoded::*;

use libafl::inputs::gramatron;
pub use gramatron::*;

use libafl::inputs::generalized;
pub use generalized::*;

use libafl::inputs::bytessub;
pub use bytessub::BytesSubInput;

use libafl::mutators::mutations::{
        BitFlipMutator, ByteAddMutator, ByteDecMutator, ByteFlipMutator, ByteIncMutator,
        ByteInterestingMutator, ByteNegMutator, ByteRandMutator, BytesCopyMutator,
        BytesDeleteMutator, BytesExpandMutator, BytesInsertCopyMutator, BytesInsertMutator,
        BytesRandInsertMutator, BytesRandSetMutator, BytesSetMutator, BytesSwapMutator, DwordAddMutator,
        DwordInterestingMutator, QwordAddMutator, WordAddMutator, WordInterestingMutator,
    };

macro_rules! random_input_from_sequence {
    ($rand:expr,$seq:expr) => {
        $rand.choose(&mut $seq.inputs).unwrap()
    };
}

macro_rules! random_input_from_corpus {
    ($state:expr) => {{
        let idx = random_corpus_id!($state.corpus(), $state.rand_mut());
        if let Some(cur) = $state.corpus().current() {
            if idx == *cur {
                return Ok(MutationResult::Skipped);
            }
        }

        let other_count = {
            let mut other_testcase = $state.corpus().get(idx).unwrap().borrow_mut();
            let other_input = other_testcase
                .load_input($state.corpus())
                .unwrap()
                .http_sequence_input();
            other_input.inputs.len()
        };
        if other_count == 0 {
            return Ok(MutationResult::Skipped);
        }

        let input_idx = $state.rand_mut().below(other_count);
        let mut other_testcase = $state.corpus().get(idx).unwrap().borrow_mut();
        other_testcase
            .load_input($state.corpus())
            .unwrap()
            .http_sequence_input()
            .inputs[input_idx]
            .clone()
    }};
}

macro_rules! swap_node {
    ($node_a:expr,$node_b:expr) => {
        unsafe {
            let parent_a = (*$node_a).parent;
            let parent_b = (*$node_b).parent;
            let idx_a = (*parent_a)
                .children
                .iter()
                .position(|x| *x == $node_a)
                .unwrap();
            let idx_b = (*parent_b)
                .children
                .iter()
                .position(|x| *x == $node_b)
                .unwrap();
            (*$node_a).parent = parent_b;
            (*$node_b).parent = parent_a;
            (*parent_a).children[idx_a] = $node_b;
            (*parent_b).children[idx_b] = $node_a;
            (*parent_a).update_metadata_up(idx_a);
            (*parent_b).update_metadata_up(idx_b);
        }
    };
}

use libafl_bolts::bolts_prelude::{tuple_list, tuple_list_type};
pub(crate) use random_input_from_corpus;
pub(crate) use random_input_from_sequence;
pub(crate) use swap_node;
use crate::mutators::quicmutator::*;

pub type QuicMutatorsTupleType = tuple_list_type!(
    // quic-level mutators
    // QuicPktTypeMutator,
    QuicSendRecvTimesMutator,
    QuicResortMutator,
    QuicFrameCyclesMutator,
    QuicFrameRepeatNumMutator,
    QuicFrameItemMutator,
    QuicAddFrameItemMutator,
    QuicDelFrameItemMutator,
    QuicFrameItemNumMutator,
    QuicFrameItemStrLenMutator,
    QuicFrameItemStrContentMutator,
    QuicFrameAddH3POSTMutator,
    QuicFrameAddH3GETMutator,
    QuicFrameCopyItemMutator,



);

pub type NSMQuicMutatorsTupleType = tuple_list_type!(
    // quic-level mutators
    // QuicPktTypeMutator,
    QuicFrameCyclesMutator,
    QuicFrameItemMutator,
    QuicAddFrameItemMutator,
    QuicDelFrameItemMutator,
    QuicFrameItemNumMutator,
    QuicFrameItemStrLenMutator,
    QuicFrameItemStrContentMutator,
);

pub type QuicBytesMutatorsTupleType = tuple_list_type!(
    BitFlipMutator,
    ByteFlipMutator,
    ByteIncMutator,
    ByteDecMutator,
    ByteNegMutator,
    ByteRandMutator,
    ByteAddMutator,
    WordAddMutator,
    DwordAddMutator,
    QwordAddMutator,
    ByteInterestingMutator,
    WordInterestingMutator,
    DwordInterestingMutator,
    BytesDeleteMutator,
    BytesDeleteMutator,
    BytesDeleteMutator,
    BytesDeleteMutator,
    BytesExpandMutator,
    BytesInsertMutator,
    BytesRandInsertMutator,
    BytesSetMutator,
    BytesRandSetMutator,
    BytesCopyMutator,
    BytesInsertCopyMutator,
    BytesSwapMutator,
);

pub fn quic_mutations() -> QuicMutatorsTupleType {
    tuple_list!(
        // QuicPktTypeMutator::new(),
        QuicSendRecvTimesMutator::new(),
        QuicResortMutator::new(),
        QuicFrameCyclesMutator::new(),
        QuicFrameRepeatNumMutator::new(),
        QuicFrameItemMutator::new(),
        QuicAddFrameItemMutator::new(),
        QuicDelFrameItemMutator::new(),
        QuicFrameItemNumMutator::new(),
        QuicFrameItemStrLenMutator::new(),
        QuicFrameItemStrContentMutator::new(),
        QuicFrameAddH3POSTMutator::new(),
        QuicFrameAddH3GETMutator::new(),
        QuicFrameCopyItemMutator::new()
    )
}


pub fn nsm_quic_mutations() -> NSMQuicMutatorsTupleType {
    tuple_list!(
        // QuicPktTypeMutator::new(),
        QuicFrameCyclesMutator::new(),
        QuicFrameItemMutator::new(),
        QuicAddFrameItemMutator::new(),
        QuicDelFrameItemMutator::new(),
        QuicFrameItemNumMutator::new(),
        QuicFrameItemStrLenMutator::new(),
        QuicFrameItemStrContentMutator::new(),
    )
}

pub fn quic_bytes_mutations() -> QuicBytesMutatorsTupleType {
    tuple_list!(
        BitFlipMutator::new(),
        ByteFlipMutator::new(),
        ByteIncMutator::new(),
        ByteDecMutator::new(),
        ByteNegMutator::new(),
        ByteRandMutator::new(),
        ByteAddMutator::new(),
        WordAddMutator::new(),
        DwordAddMutator::new(),
        QwordAddMutator::new(),
        ByteInterestingMutator::new(),
        WordInterestingMutator::new(),
        DwordInterestingMutator::new(),
        BytesDeleteMutator::new(),
        BytesDeleteMutator::new(),
        BytesDeleteMutator::new(),
        BytesDeleteMutator::new(),
        BytesExpandMutator::new(),
        BytesInsertMutator::new(),
        BytesRandInsertMutator::new(),
        BytesSetMutator::new(),
        BytesRandSetMutator::new(),
        BytesCopyMutator::new(),
        BytesInsertCopyMutator::new(),
        BytesSwapMutator::new(),
    )
}
