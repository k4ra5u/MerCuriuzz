use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::path::PathBuf;
use std::{
    any::Any, env, ffi::{OsStr, OsString}, fs::File, io::{self, prelude::*, BufRead, ErrorKind, Read, Write}, os::{
        fd::{AsRawFd, BorrowedFd},
        unix::{io::RawFd, process::CommandExt},
    }, path::Path, process::{Child, Command, Output, Stdio}, str, thread::sleep, vec
};
use libafl_bolts::shmem::ShMemId;
use nix::sys::signal::sigprocmask;
use nix::{
    sys::{
        select::{pselect, FdSet},
        signal::{kill, SigSet, Signal},
        time::TimeSpec,
        wait::waitpid,
    },
    unistd::Pid,
};
use clap::Parser;


use nix::libc::{rand, seccomp_notif_addfd};
use nix::{libc::srand};
use rand::Rng;
use mylibafl::{
    executors::NetworkRestartExecutor, feedbacks::*, inputstruct::QuicStruct, mutators::quic_mutations, observers::*, schedulers::MCTSScheduler
};
use mylibafl::inputstruct::*;
use libafl_bolts::ownedref::OwnedMutSlice;
use libafl_bolts::{
    current_nanos,
    rands::StdRand,
    shmem::{ShMem, ShMemProvider, UnixShMemProvider, StdShMemProvider, UnixShMem},
    tuples::{tuple_list, Handled, MatchNameRef, Merge},
    AsSliceMut, Truncate,
};
// use libafl_targets::{edges_max_num, DifferentialAFLMapSwapObserver};
use log::{error, info,debug,warn};
use ctrlc;
use quiche::{frame, packet, stream::RangeBuf, Connection, ConnectionId, Error, Header};
use ring::aead::quic;

pub fn main() {
    const MAP_SIZE: usize = 1048260;

    while(true) {
        sleep(Duration::from_secs(1));
        // let shmem_id = std::env::var("QUIC_STRUCT").unwrap();
        let shmem_id = "164883";
        println!("shm_buf: {:?}", shmem_id);
        let mut quic_shmem_provider = UnixShMemProvider::new().unwrap();
        let mut quic_shmem = quic_shmem_provider.shmem_from_id_and_size(
            ShMemId::from_string(&format!("{shmem_id}")),
            MAP_SIZE
        ).unwrap();
        let quic_shmem_buf = quic_shmem.as_slice_mut();
        let quic_shmem_len = u64::from_be_bytes(quic_shmem_buf[0..8].try_into().expect("")) as usize;
        // println!("quic_shmem_buf: {:?}", &quic_shmem_buf[8..8+quic_shmem_len]);
        let new_len = unsafe { rand() } as usize % 20;
        quic_shmem_buf[0..8].copy_from_slice(&new_len.to_be_bytes());
        for i in 0..new_len  {
            quic_shmem_buf[8+i] = unsafe { rand() } as u8;
        }

    
    }

}