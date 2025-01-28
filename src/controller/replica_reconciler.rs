use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use kube::runtime::{watcher, Controller};
use kube::Api;
use kube::{runtime::controller::Action, Client};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::controller::crd::PolicyRevision;
use crate::evaluation::EvaluationEnvironment;

pub struct Context {
    pub client: Client,
    evaluation_environment: Arc<RwLock<EvaluationEnvironment>>,
}

#[derive(Error, Debug)]
pub enum ReconciliationError {
    #[error("KubeError: {0}")]
    KubeError(kube::Error),
}

pub async fn reconcile(
    policy_revision: Arc<PolicyRevision>,
    ctx: Arc<Context>,
) -> Result<Action, ReconciliationError> {
    info!(
        "Reconciling PolicyRevision: {}",
        policy_revision.metadata.name.as_ref().unwrap()
    );

    Ok(Action::await_change())
}

pub async fn run(ctx: Arc<Context>) {
    let api = Api::<PolicyRevision>::all(ctx.client.clone());

    Controller::new(api, watcher::Config::default().any_semantic())
        // .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .filter_map(|x| async move { std::result::Result::ok(x) })
        .for_each(|_| futures::future::ready(()))
        .await;
}

fn error_policy(
    policy_revision: Arc<PolicyRevision>,
    error: &ReconciliationError,
    ctx: Arc<Context>,
) -> Action {
    warn!("reconcile failed: {:?}", error);
    Action::requeue(Duration::from_secs(5 * 60))
}

