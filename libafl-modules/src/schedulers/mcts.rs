use std::borrow::Cow;

use libafl::{corpus::Testcase, inputs::HasMutatorBytes, prelude::ObserversTuple, state::HasRand};
use libafl_bolts::{
    ownedref::OwnedMutPtr,
    rands::Rand,
    tuples::{Handle, Handled,MatchNameRef},
    Named,
    Error,
    tuples::MatchName
};

use log::info;
use mio::unix::pipe::new;
use serde::{Deserialize, Serialize};
use libafl::{executors::ExitKind, inputs::UsesInput,observers::Observer, state::UsesState};
use quiche::{frame, packet, Connection, ConnectionId, Header};
use crate::{
    observers::*,
    inputstruct::*
};
// use alloc::borrow::ToOwned;
use core::marker::PhantomData;
use libafl::{
    corpus::{Corpus, CorpusId, HasTestcase},
    schedulers::{RemovableScheduler, Scheduler,AflScheduler},
    state::{HasCorpus, State},
};
use hashbrown::HashMap;
use std::rc::Rc;
use std::cell::RefCell;


/// The Metadata for `MCTSScheduler`
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny


#[derive( Clone, Debug)]

pub struct MCTSNode{
    pub corpus_id: CorpusId,
    pub parent: Option<Rc<RefCell<MCTSNode>>>,
    pub children: Vec<Rc<RefCell<MCTSNode>>>,
    pub reward: f64,
    pub visits: u64,
    pub action: usize,
    pub untried_actions: Vec<usize>,
}
impl MCTSNode {
    pub fn new() -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self {
            corpus_id: CorpusId(0),
            parent: None,
            children: Vec::new(),
            reward: 0.0,
            visits: 0,
            action: 0,
            untried_actions: Vec::new(),
        }))
    }

    pub fn add_child(parent: &Rc<RefCell<Self>>,new_node:Rc<RefCell<MCTSNode>>,reward: f64) {        
        // let new_node = MCTSNode::new();
        new_node.borrow_mut().parent = Some(parent.clone());
        let new_node_clone = new_node.clone();
        parent.borrow_mut().children.push(new_node);
        new_node_clone.borrow_mut().backpropagate(reward);
        
    }

    pub fn set_parent(child: &Rc<RefCell<Self>>, parent:  &Rc<RefCell<MCTSNode>>) {
        child.borrow_mut().parent = Some(parent.clone());
        parent.borrow_mut().children.push(child.clone());
    }

    pub fn del_target_child(target: &Rc<RefCell<MCTSNode>>) {
        // 获取 target 的父节点
        let parent = target.borrow().parent.as_ref().unwrap().clone();

        // 删除 parent.children 中的 target 元素
        parent.borrow_mut().children.retain(|child| !Rc::ptr_eq(child, target));
    }

    pub fn best_child(&self, c: f64) -> Option<Rc<RefCell<MCTSNode>>> {
        self.children.iter()
            .max_by(|a, b| {
                let a_node = a.borrow();
                let b_node = b.borrow();

                let ucb1_a = a_node.reward / (a_node.visits as f64) 
                    + c * ((self.visits as f64).ln() / (a_node.visits as f64)).sqrt();
                let ucb1_b = b_node.reward / (b_node.visits as f64) 
                    + c * ((self.visits as f64).ln() / (b_node.visits as f64)).sqrt();

                ucb1_a.partial_cmp(&ucb1_b).unwrap()
            })
            .cloned()
    }

    pub fn update(&mut self, reward: f64) {
        self.visits += 1;
        self.reward += reward;
    }

    pub fn backpropagate(&mut self, reward: f64){
        self.update(reward);
        if let Some(parent) = &self.parent {
            parent.borrow_mut().backpropagate(reward);
        }
    }
}


#[derive(Clone, Debug)]
pub struct MCTSScheduler<S> {
    root_node: Rc<RefCell<MCTSNode>>,
    cur_select_node: Rc<RefCell<MCTSNode>>,
    phantom: PhantomData<S>,
    observer_handle: Handle<UCBObserver>,
    evaluate_res: f64,
}

impl<S> MCTSScheduler<S>
where
    S: HasCorpus + HasRand + HasTestcase + State,
{
    #[must_use]
    pub fn new(observer: &UCBObserver) -> Self {
        let root_node = MCTSNode::new();
        root_node.borrow_mut().corpus_id = libafl::corpus::CorpusId(usize::MAX);
        let cur_select_node = root_node.clone();
        Self {
            root_node,
            cur_select_node,
            observer_handle: observer.handle(),
            phantom: PhantomData,
            evaluate_res: 0.0
        }
    }
    
    pub fn mcts_search_node(&mut self) {
        let mut node = self.root_node.clone();

        while !node.borrow().children.is_empty() {
            let node_mut = node.borrow().best_child(1.414).unwrap(); 
            node = node_mut;
        }
        self.cur_select_node = node.clone();

    }

    pub fn observer_handle(&self) -> Handle<UCBObserver> {
        self.observer_handle.clone()
    }

    pub fn evaluate<OT>(
        &mut self,
        _input: &<S as UsesInput>::Input,
        observers: &OT,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<S>,
    {

        Ok(())
    }

    pub fn draw_mcts_tree(&self) {
        fn print_node(node: &Rc<RefCell<MCTSNode>>, depth: usize) {
            let node_borrow = node.borrow();
            // 打印缩进
            for _ in 0..depth {
                print!("  ");
            }
            // 打印节点信息
            println!("└─ corpus_id: {:?}, reward: {:?}, visits: {:?}", node_borrow.corpus_id, node_borrow.reward, node_borrow.visits);
            // 递归打印子节点
            for child in &node_borrow.children {
                print_node(child, depth + 1);
            }
        }
    
        print_node(&self.root_node, 0);
    }

}

impl<S> UsesState for MCTSScheduler<S>
where
    S: State,
{
    type State = S;
}

impl<S> RemovableScheduler for MCTSScheduler<S>
where

    S: HasCorpus + HasRand + HasTestcase + State,
{
    /// This will *NOT* neutralize the effect of this removed testcase from the global data such as `SchedulerMetadata`
    fn on_remove(
        &mut self,
        _state: &mut Self::State,
        _id: CorpusId,
        _prev: &Option<Testcase<<Self::State as UsesInput>::Input>>,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// This will *NOT* neutralize the effect of this removed testcase from the global data such as `SchedulerMetadata`
    fn on_replace(
        &mut self,
        _state: &mut Self::State,
        _id: CorpusId,
        _prev: &Testcase<<Self::State as UsesInput>::Input>,
    ) -> Result<(), Error> {
        Ok(())
    }
}


impl<S> Scheduler for MCTSScheduler<S>
where
    S: HasCorpus + HasRand + HasTestcase + State,
{
    /// Called when a [`Testcase`] is added to the corpus
    fn on_add(&mut self, state: &mut S, id: CorpusId) -> Result<(), Error> {
        // let current_id = *state.corpus().current();
        let current_id = self.cur_select_node.borrow().corpus_id;
        state
            .corpus()
            .get(id)?
            .borrow_mut()
            .set_parent_id_optional(Some(current_id));
        let new_node = MCTSNode::new();
        let cur_node = self.cur_select_node.clone();
        new_node.borrow_mut().corpus_id = id;
        // let rand_0 = state.rand_mut().below(10000);
        // let rand_0_1 = rand_0 as f64 / 10000.0;
        // new_node.borrow_mut().reward = rand_0_1;
        MCTSNode::add_child(&cur_node, new_node,self.evaluate_res);
        info!("Add new node: {:?},reward:{:?}", id,self.evaluate_res);
        // self.draw_mcts_tree();
        Ok(())
    }

    fn on_evaluation<OT>(
        &mut self,
        state: &mut Self::State,
        input: &<Self::State as UsesInput>::Input,
        observers: &OT,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<Self::State>,
    {
        let observer = observers.get(&self.observer_handle).unwrap();
        self.evaluate_res = observer.get_reward();

        Ok(())
        // self.evaluate(state, input, observers)
    }

    #[allow(clippy::similar_names, clippy::cast_precision_loss)]
    fn next(&mut self, state: &mut S) -> Result<CorpusId, Error> {
        if state.corpus().count() == 0 {
            Err(Error::empty(
                "No entries in corpus. This often implies the target is not properly instrumented."
                    .to_owned(),
            ))
        } else {
            self.mcts_search_node();
            let id = self.cur_select_node.borrow().corpus_id;
            // let id = state
            //     .corpus()
            //     .current()
            //     .map(|id| state.corpus().next(id))
            //     .flatten()
            //     .unwrap_or_else(|| state.corpus().first().unwrap());
            self.set_current_scheduled(state, Some(id))?;
            Ok(id)
        }
    }
}
