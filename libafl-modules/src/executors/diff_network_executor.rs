use std::{
    any::Any, env, ffi::{OsStr, OsString}, io::{self, prelude::*, ErrorKind, Read, Write}, os::{
        fd::{AsRawFd, BorrowedFd},
        unix::{io::RawFd, process::CommandExt},
    }, path::Path, process::{Child, Command, Output, Stdio}, str, thread::sleep, time::Duration, vec
};
use std::num::ParseIntError;
use libc::{CODA_SUPER_MAGIC, ERA};
use nix::{
    sys::{
        select::{pselect, FdSet},
        signal::{kill, SigSet, Signal},
        time::TimeSpec,
        wait::waitpid,
    },
    unistd::Pid,
};
use libafl::{
    corpus::Corpus, executors::{
        Executor, ExitKind, HasObservers
    }, inputs::HasTargetBytes, observers::{
        get_asan_runtime_flags_with_log_path, AsanBacktraceObserver, ObserversTuple, UsesObservers
    }, state::{
        HasCorpus, HasExecutions, State, UsesState
    }
};
use libafl_bolts::{
    rands, shmem::{ShMem, ShMemProvider, UnixShMemProvider}, tuples::{Handle, Handled,MatchName ,MatchNameRef, Prepend, RefIndexable}, AsSlice, AsSliceMut, Truncate
};
use rand::Rng;
use std::net::{SocketAddr, ToSocketAddrs};
use ring::rand::*;
use log::{error, info,debug,warn};

use quiche::{frame, packet, Connection, ConnectionId, Error, Header};

use crate::inputstruct::{pkt_resort_type, quic_input::InputStruct_deserialize, FramesCycleStruct, InputStruct, QuicStruct};
use crate::observers::*;
use crate::misc::*;

//use crate::QuicStruct;
// use quic_input::{FramesCycleStruct, InputStruct, pkt_resort_type, QuicStruct};
