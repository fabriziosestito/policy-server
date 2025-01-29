use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use kube::runtime::{watcher, Controller};
use kube::Api;
use kube::{runtime::controller::Action, Client};
use policy_evaluator::evaluation_context::EvaluationContext;
use policy_evaluator::kubewarden_policy_sdk::crd::policies::admission_policy::AdmissionPolicySpec;
use policy_evaluator::wasmtime;
use thiserror::Error;
use tracing::{error, info, warn};

use policy_evaluator::kubewarden_policy_sdk::crd::policies::AdmissionPolicy;

use crate::config::{PolicyOrPolicyGroupSettings, SettingsJSON};
use crate::controller::crd::PolicyRevision;
use crate::evaluation::precompiled_policy::PrecompiledPolicy;
use crate::evaluation::{PolicyEvaluationSettings, PolicyID, SharedEvaluationEnvironment};

pub struct Context {
    pub client: Client,
    pub evaluation_environment: SharedEvaluationEnvironment,
    pub engine: wasmtime::Engine,
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

    let policy_spec: AdmissionPolicySpec =
        match serde_json::from_value(policy_revision.spec.data.0.clone()) {
            Ok(policy) => policy,
            Err(e) => {
                error!("Failed to deserialize the policy: {}", e);
                return Ok(Action::await_change());
            }
        };

    dbg!(policy_revision.spec.data.0.clone());

    let policy_path = policy_spec.module;
    let precompiled_policy = PrecompiledPolicy::new(&ctx.engine, Path::new(&policy_path)).unwrap();
    let settings_json: serde_json::Map<String, serde_json::Value> =
        serde_json::from_value(policy_spec.settings.0).unwrap();
    let policy_evaluation_settings = PolicyEvaluationSettings {
        policy_mode: crate::config::PolicyMode::Protect,
        allowed_to_mutate: false,
        settings: PolicyOrPolicyGroupSettings::Policy(SettingsJSON(settings_json)),
    };

    let eval_ctx = EvaluationContext {
        policy_id: policy_revision.metadata.name.as_ref().unwrap().to_owned(),
        callback_channel: None,
        ctx_aware_resources_allow_list: Default::default(),
    };

    ctx.evaluation_environment.register(
        &ctx.engine,
        &PolicyID::Policy(policy_revision.metadata.name.as_ref().unwrap().to_owned()),
        policy_evaluation_settings,
        eval_ctx,
        &precompiled_policy,
        Some(2000),
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
