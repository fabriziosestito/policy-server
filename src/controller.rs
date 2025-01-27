use k8s_openapi::apimachinery::pkg::runtime::RawExtension;
use kube::{
    self,
    api::{Api, ListParams, Patch, PatchParams, ResourceExt},
    client::Client,
    runtime::{
        controller::{Action, Controller},
        events::{Event, EventType, Recorder, Reporter},
        finalizer::{finalizer, Event as Finalizer},
        watcher::Config,
    },
    CustomResource, Resource,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[cfg_attr(test, derive(Default))]
#[kube(
    kind = "PolicyRevision",
    group = "policies.kubewarden.io",
    version = "v1",
    namespaced
)]
#[kube(status = "PolicyRevisionStatus", shortname = "psrv")]
pub struct PolicyRevisionSpec {
    pub data: RawExtension,
    pub enabled: bool,
}

#[derive(Deserialize, Serialize, Clone, Default, Debug, JsonSchema)]
pub struct PolicyRevisionStatus {}
