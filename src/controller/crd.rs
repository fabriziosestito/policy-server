use k8s_openapi::apimachinery::pkg::runtime::RawExtension;
use kube::{self, CustomResource};
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

#[cfg(test)]
mod test {
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
    use ktest::ktest;
    use kube::{
        api::{ObjectMeta, Patch, PatchParams},
        runtime::{conditions, wait::await_condition},
        Api, CustomResourceExt,
    };

    use super::*;

    #[ktest]
    #[tokio::test]
    async fn test_create_crd() {
        // TODO: should this be moved to ktest?
        let crds: Api<CustomResourceDefinition> = Api::all(client.clone());
        let ssapply = PatchParams::apply("test").force();
        crds.patch(
            "policyrevisions.policies.kubewarden.io",
            &ssapply,
            &Patch::Apply(PolicyRevision::crd()),
        )
        .await
        .unwrap();

        let establish = await_condition(
            crds,
            "policyrevisions.policies.kubewarden.io",
            conditions::is_crd_established(),
        );
        let _ = tokio::time::timeout(std::time::Duration::from_secs(10), establish)
            .await
            .unwrap();

        let api: Api<PolicyRevision> = Api::default_namespaced(client);

        let pp = kube::api::PostParams::default();
        let _ = api
            .create(
                &pp,
                &PolicyRevision {
                    metadata: ObjectMeta {
                        name: Some("test-policy-revision".to_string()),
                        namespace: Some("default".to_string()),
                        ..Default::default()
                    },
                    spec: PolicyRevisionSpec {
                        data: RawExtension(serde_json::json!({
                            "name": "test-policy",
                            "version": "v1",
                            "rules": [],
                        })),
                        enabled: true,
                    },
                    status: Default::default(),
                },
            )
            .await
            .expect("Failed to create PolicyRevision");
    }
}
