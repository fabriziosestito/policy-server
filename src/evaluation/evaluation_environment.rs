use policy_evaluator::{
    admission_response::{AdmissionResponse, AdmissionResponseStatus},
    callback_requests::CallbackRequest,
    evaluation_context::EvaluationContext,
    kubewarden_policy_sdk::settings::SettingsValidationResponse,
    policy_evaluator::{PolicyEvaluator, PolicyEvaluatorPre, PolicyExecutionMode, ValidateRequest},
    policy_evaluator_builder::PolicyEvaluatorBuilder,
    policy_metadata::ContextAwareResource,
    wasmtime,
};
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::mpsc;
use tracing::debug;

use crate::{
    config::{Policy, PolicyMode, PolicySettings},
    evaluation::{
        errors::{EvaluationError, Result},
        policy_evaluation_settings::PolicyEvaluationSettings,
        precompiled_policy::{PrecompiledPolicies, PrecompiledPolicy},
    },
};

#[cfg(test)]
use mockall::automock;

/// `Validator` is the main structure that is used to validate the requests.
/// It was created because of the group policies feature. Due to Rust borrowing rules,
/// and how Rhai works, it is not possible to have a single `EvaluationEnvironment` shared across
/// all the threads. The `EvaluationEnvironment` had to be put inside of a `std::sync::Arc` to
/// be shared across threads.
///
/// `Validator` holds the `Arc` reference to the `EvaluationEnvironment` and is the struct that
/// gets mocked during the tests.
#[derive(Default)]
#[cfg_attr(test, allow(dead_code))]
pub(crate) struct Validator {
    /// The name of the Namespace where Policy Server doesn't operate. All the requests
    /// involving this Namespace are going to be accepted. This is usually done to prevent user
    /// policies from messing with the components of the Kubewarden stack (which are all
    /// deployed inside of the same Namespace).
    always_accept_admission_reviews_on_namespace: Option<String>,

    /// The `EvaluationEnvironment` doing the actual work. It is wrapped inside of an
    /// `Arc` to be shared across threads.
    evaluation_environment: Arc<EvaluationEnvironment>,
}

#[cfg_attr(test, automock)]
#[cfg_attr(test, allow(dead_code))]
impl Validator {
    /// Creates a new `Validator`
    pub(crate) fn new(
        engine: &wasmtime::Engine,
        policies: &HashMap<String, Policy>,
        precompiled_policies: &PrecompiledPolicies,
        always_accept_admission_reviews_on_namespace: Option<String>,
        policy_evaluation_limit_seconds: Option<u64>,
        callback_handler_tx: mpsc::Sender<CallbackRequest>,
        continue_on_errors: bool,
    ) -> Result<Self> {
        let evaluation_environment = EvaluationEnvironment::new(
            engine,
            policies,
            precompiled_policies,
            policy_evaluation_limit_seconds,
            callback_handler_tx,
            continue_on_errors,
        )?;

        Ok(Self {
            always_accept_admission_reviews_on_namespace,
            evaluation_environment: Arc::new(evaluation_environment),
        })
    }

    /// Returns `true` if the given `namespace` is the special Namespace that is ignored by all
    /// the policies
    pub(crate) fn should_always_accept_requests_made_inside_of_namespace(
        &self,
        namespace: &str,
    ) -> bool {
        self.always_accept_admission_reviews_on_namespace.as_deref() == Some(namespace)
    }

    /// Given a policy ID, return how the policy operates
    pub fn get_policy_mode(&self, policy_id: &str) -> Result<PolicyMode> {
        self.evaluation_environment.get_policy_mode(policy_id)
    }

    /// Given a policy ID, returns true if the policy is allowed to mutate
    pub fn get_policy_allowed_to_mutate(&self, policy_id: &str) -> Result<bool> {
        self.evaluation_environment
            .get_policy_allowed_to_mutate(policy_id)
    }

    /// Perform a request validation
    pub fn validate(&self, policy_id: &str, req: &ValidateRequest) -> Result<AdmissionResponse> {
        if self
            .evaluation_environment
            .group_policies
            .contains(policy_id)
        {
            EvaluationEnvironment::validate_group_policy(
                self.evaluation_environment.clone(),
                policy_id,
                req,
            )
        } else {
            EvaluationEnvironment::validate_individual_policy(
                self.evaluation_environment.clone(),
                policy_id,
                req,
            )
        }
    }
}

/// This structure contains all the policies defined by the user inside of the `policies.yml`.
/// It also provides helper methods to perform the validation of a request and the validation
/// of the settings provided by the user.
///
/// This is an immutable structure that can be safely shared across different threads once wrapped
/// inside of a `Arc`.
///
/// When performing a `validate` or `validate_settings` operation, a new WebAssembly environment is
/// created and used to perform the operation. The environment is then discarded once the
/// evaluation is over.
/// This ensures:
/// - no memory leaks caused by bogus policies affect the Policy Server long running process
/// - no data is shared between evaluations of the same module
///
/// To reduce the creation time, this code makes use of `PolicyEvaluatorPre` which are created
/// only once, during the bootstrap phase.
#[derive(Default)]
pub(crate) struct EvaluationEnvironment {
    /// A map with the module digest as key, and the associated `PolicyEvaluatorPre`
    /// as value
    module_digest_to_policy_evaluator_pre: HashMap<String, PolicyEvaluatorPre>,

    /// A map with the ID of the policy as value, and the associated `EvaluationContext` as
    /// value.
    /// In this case, `policy_id` is the name of the policy as  declared inside of the
    /// `policies.yml` file. These names are guaranteed to be unique.
    policy_id_to_eval_ctx: HashMap<String, EvaluationContext>,

    /// Map a `policy_id` (the name given by the user inside of `policies.yml`) to the
    /// module's digest. This allows us to deduplicate the Wasm modules defined by the user.
    policy_id_to_module_digest: HashMap<String, String>,

    /// Map a `policy_id` to the `PolicyEvaluationSettings` instance. This allows us to obtain
    /// the list of settings to be used when evaluating a given policy.
    policy_id_to_settings: HashMap<String, PolicyEvaluationSettings>,

    /// A map with the policy ID as key, and the error message as value.
    /// This is used to store the errors that occurred during policies initialization.
    /// The errors can occur in the fetching of the policy, or in the validation of the settings.
    policy_initialization_errors: HashMap<String, String>,

    /// A Set containing the IDs of the group policies. The ID is the name of the policy as
    /// declared inside of the `policies.yml` file.
    group_policies: HashSet<String>,
}

impl EvaluationEnvironment {
    /// Creates a new `EvaluationEnvironment`
    fn new(
        engine: &wasmtime::Engine,
        policies: &HashMap<String, Policy>,
        precompiled_policies: &PrecompiledPolicies,
        policy_evaluation_limit_seconds: Option<u64>,
        callback_handler_tx: mpsc::Sender<CallbackRequest>,
        continue_on_errors: bool,
    ) -> Result<Self> {
        let mut eval_env = Self {
            ..Default::default()
        };

        for (public_name, policy) in policies {
            match policy {
                Policy::Individual {
                    url,
                    policy_mode,
                    allowed_to_mutate,
                    context_aware_resources,
                    ..
                } => {
                    let policy_identifier = public_name;
                    let precompiled_policy = precompiled_policies.get(url).ok_or_else(|| {
                        EvaluationError::BootstrapFailure(format!(
                            "cannot find precompiled policy of {}",
                            public_name
                        ))
                    })?;

                    let precompiled_policy = match precompiled_policy.as_ref() {
                        Ok(precompiled_policy) => precompiled_policy,
                        Err(e) => {
                            eval_env
                                .policy_initialization_errors
                                .insert(public_name.clone(), e.to_string());
                            continue;
                        }
                    };

                    let policy_evaluation_settings = PolicyEvaluationSettings {
                        policy_mode: policy_mode.clone(),
                        allowed_to_mutate: allowed_to_mutate.unwrap_or(false),
                        settings: policy.settings().map_err(|e| {
                            EvaluationError::BootstrapFailure(format!(
                                "cannot extract settings from policy: {e}"
                            ))
                        })?,
                    };

                    eval_env
                        .register(
                            engine,
                            policy_identifier,
                            policy_evaluation_settings,
                            context_aware_resources,
                            precompiled_policy,
                            callback_handler_tx.clone(),
                            policy_evaluation_limit_seconds,
                        )
                        .map_err(|e| EvaluationError::BootstrapFailure(e.to_string()))?;

                    eval_env.validate_settings(policy_identifier, continue_on_errors)?;
                }
                Policy::Group {
                    policy_mode,
                    policies,
                    ..
                } => {
                    let policy_evaluation_settings = PolicyEvaluationSettings {
                        policy_mode: policy_mode.clone(),
                        allowed_to_mutate: false, // Group policies are not allowed to mutate
                        settings: policy.settings().map_err(|e| {
                            EvaluationError::BootstrapFailure(format!(
                                "cannot extract settings from policy: {e}"
                            ))
                        })?,
                    };
                    eval_env.register_group_policy(public_name, policy_evaluation_settings);

                    for (sub_policy_name, sub_policy) in policies {
                        let policy_identifier = format!("{public_name}/{sub_policy_name}");
                        let precompiled_policy =
                            precompiled_policies.get(&sub_policy.url).ok_or_else(|| {
                                EvaluationError::BootstrapFailure(format!(
                                    "cannot find precompiled policy of {}",
                                    sub_policy_name
                                ))
                            })?;

                        let precompiled_policy = match precompiled_policy.as_ref() {
                            Ok(precompiled_policy) => precompiled_policy,
                            Err(e) => {
                                eval_env.policy_initialization_errors.insert(
                                    format!("{public_name}/{sub_policy_name}"),
                                    e.to_string(),
                                );
                                continue;
                            }
                        };

                        let policy_evaluation_settings = PolicyEvaluationSettings {
                            policy_mode: policy_mode.clone(),
                            allowed_to_mutate: false, // Group policies are not allowed to mutate
                            settings: sub_policy.settings().map_err(|e| {
                                EvaluationError::BootstrapFailure(format!(
                                    "cannot extract settings from policy: {e}"
                                ))
                            })?,
                        };

                        eval_env
                            .register(
                                engine,
                                &policy_identifier,
                                policy_evaluation_settings,
                                &sub_policy.context_aware_resources,
                                precompiled_policy,
                                callback_handler_tx.clone(),
                                policy_evaluation_limit_seconds,
                            )
                            .map_err(|e| EvaluationError::BootstrapFailure(e.to_string()))?;

                        eval_env.validate_settings(&policy_identifier, continue_on_errors)?;
                    }
                }
            }
        }

        Ok(eval_env)
    }

    /// Register a new policy. It takes care of creating a new `PolicyEvaluator` (when needed).
    /// This is used to register both individual policies and the ones that are part of a group
    /// policy.
    ///
    /// Params:
    /// - `engine`: the `wasmtime::Engine` to be used when creating the `PolicyEvaluator`
    /// - `policy_id`: the unique identifier of the policy
    /// - `precompiled_policy`: the `PrecompiledPolicy` associated with the Wasm module referenced
    ///    by the policy
    /// - `policy`: a data structure that maps all the information defined inside of
    ///    `policies.yml` for the given policy
    /// - `callback_handler_tx`: the transmission end of a channel that connects the worker
    ///   with the asynchronous world
    /// - `policy_evaluation_limit_seconds`: when set, defines after how many seconds the
    ///   policy evaluation is interrupted
    #[allow(clippy::too_many_arguments)]
    fn register(
        &mut self,
        engine: &wasmtime::Engine,
        policy_id: &str,
        policy_evaluation_settings: PolicyEvaluationSettings,
        context_aware_resources: &BTreeSet<ContextAwareResource>,
        precompiled_policy: &PrecompiledPolicy,
        callback_handler_tx: mpsc::Sender<CallbackRequest>,
        policy_evaluation_limit_seconds: Option<u64>,
    ) -> Result<()> {
        let module_digest = &precompiled_policy.digest;

        if !self
            .module_digest_to_policy_evaluator_pre
            .contains_key(module_digest)
        {
            debug!(?policy_id, "create wasmtime::Module");
            let module = create_wasmtime_module(policy_id, engine, precompiled_policy)?;
            debug!(?policy_id, "create PolicyEvaluatorPre");
            let pol_eval_pre = create_policy_evaluator_pre(
                engine,
                &module,
                precompiled_policy.execution_mode,
                policy_evaluation_limit_seconds,
            )?;

            self.module_digest_to_policy_evaluator_pre
                .insert(module_digest.to_owned(), pol_eval_pre);
        }
        self.policy_id_to_module_digest
            .insert(policy_id.to_owned(), module_digest.to_owned());

        self.policy_id_to_settings
            .insert(policy_id.to_owned(), policy_evaluation_settings);

        let eval_ctx = EvaluationContext {
            policy_id: policy_id.to_owned(),
            callback_channel: Some(callback_handler_tx.clone()),
            ctx_aware_resources_allow_list: context_aware_resources.to_owned(),
        };
        self.policy_id_to_eval_ctx
            .insert(policy_id.to_owned(), eval_ctx);

        Ok(())
    }

    fn register_group_policy(
        &mut self,
        policy_id: &str,
        policy_evaluation_settings: PolicyEvaluationSettings,
    ) {
        self.policy_id_to_settings
            .insert(policy_id.to_owned(), policy_evaluation_settings);
        self.group_policies.insert(policy_id.to_owned());
    }

    /// Given a policy ID, return how the policy operates
    fn get_policy_mode(&self, policy_id: &str) -> Result<PolicyMode> {
        self.policy_id_to_settings
            .get(policy_id)
            .map(|settings| settings.policy_mode.clone())
            .ok_or(EvaluationError::PolicyNotFound(policy_id.to_string()))
    }

    /// Given a policy ID, returns true if the policy is allowed to mutate
    fn get_policy_allowed_to_mutate(&self, policy_id: &str) -> Result<bool> {
        self.policy_id_to_settings
            .get(policy_id)
            .map(|settings| settings.allowed_to_mutate)
            .ok_or(EvaluationError::PolicyNotFound(policy_id.to_string()))
    }

    /// Given a policy ID, returns the settings provided by the user inside of `policies.yml`
    fn get_policy_settings(&self, policy_id: &str) -> Result<PolicyEvaluationSettings> {
        let settings = self
            .policy_id_to_settings
            .get(policy_id)
            .ok_or(EvaluationError::PolicyNotFound(policy_id.to_string()))?
            .clone();

        Ok(settings)
    }

    /// Validate the settings the user provided for the given policy
    fn validate_settings(
        &mut self,
        policy_id: &str,
        continue_on_policy_initialization_errors: bool,
    ) -> Result<()> {
        let settings = self.get_policy_settings(policy_id)?;

        match &settings.settings {
            PolicySettings::IndividualPolicy(settings) => {
                let mut evaluator = self.rehydrate(policy_id)?;
                match evaluator.validate_settings(&settings.clone().into()) {
                    SettingsValidationResponse {
                        valid: true,
                        message: _,
                    } => {}
                    SettingsValidationResponse {
                        valid: false,
                        message,
                    } => {
                        let error_message = format!(
                            "Policy settings are invalid: {}",
                            message.unwrap_or("no message".to_owned())
                        );

                        if !continue_on_policy_initialization_errors {
                            return Err(EvaluationError::PolicyInitialization(error_message));
                        }

                        self.policy_initialization_errors
                            .insert(policy_id.to_string(), error_message.clone());
                    }
                };
            }
            PolicySettings::GroupPolicy { sub_policies, .. } => {
                // TODO: validate the group policy expression
                for sub_policy_id in sub_policies {
                    if let Err(e) = self
                        .validate_settings(sub_policy_id, continue_on_policy_initialization_errors)
                    {
                        if !continue_on_policy_initialization_errors {
                            return Err(e);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Internal method, create a `PolicyEvaluator` by using a pre-initialized instance
    fn rehydrate(&self, policy_id: &str) -> Result<PolicyEvaluator> {
        if self.group_policies.contains(policy_id) {
            return Err(EvaluationError::GroupPolicyUsedAsIndividualPolicy(format!(
                "attempted to rehydrate {policy_id}"
            )));
        }

        let module_digest = self
            .policy_id_to_module_digest
            .get(policy_id)
            .ok_or(EvaluationError::PolicyNotFound(policy_id.to_string()))?;
        let policy_evaluator_pre = self
            .module_digest_to_policy_evaluator_pre
            .get(module_digest)
            .ok_or(EvaluationError::PolicyNotFound(policy_id.to_string()))?;

        let eval_ctx = self
            .policy_id_to_eval_ctx
            .get(policy_id)
            .ok_or(EvaluationError::PolicyNotFound(policy_id.to_string()))?;

        policy_evaluator_pre.rehydrate(eval_ctx).map_err(|e| {
            EvaluationError::WebAssemblyError(format!("cannot rehydrate PolicyEvaluatorPre: {e}"))
        })
    }

    /// Validate a single policy.
    ///
    /// Note, this is a static method because it is invoked from within a closure that is
    /// passed to the Rhai engine. That requires the `evaluation_environment` to be cloned,
    /// hence to be placed inside of an `Arc`.
    fn validate_individual_policy(
        eval_env: Arc<EvaluationEnvironment>,
        policy_id: &str,
        req: &ValidateRequest,
    ) -> Result<AdmissionResponse> {
        debug!(?policy_id, "validate individual policy");

        if let Some(error) = eval_env.policy_initialization_errors.get(policy_id) {
            return Err(EvaluationError::PolicyInitialization(error.to_string()));
        }

        let settings: serde_json::Map<String, serde_json::Value> =
            match eval_env.get_policy_settings(policy_id)?.settings {
                PolicySettings::IndividualPolicy(settings) => settings.into(),
                _ => unreachable!(),
            };
        let mut evaluator = eval_env.rehydrate(policy_id)?;

        Ok(evaluator.validate(req.clone(), &settings))
    }

    fn validate_group_policy(
        eval_env: Arc<EvaluationEnvironment>,
        policy_id: &str,
        req: &ValidateRequest,
    ) -> Result<AdmissionResponse> {
        let (expression, message, sub_policy_names) =
            match eval_env.get_policy_settings(policy_id)?.settings {
                PolicySettings::GroupPolicy {
                    expression,
                    message,
                    sub_policies,
                } => (expression, message, sub_policies),
                _ => unreachable!(),
            };

        // TODO: reduce the amount of features exposed to the Rhai expression. For example, do not
        // allow usage of `for` loops
        // TODO: speed up code by caching the Rhai expression AST
        let mut rhai_engine = rhai::Engine::new_raw();

        for sub_policy_name in sub_policy_names {
            let sub_policy_id = format!("{policy_id}/{sub_policy_name}");
            let rhai_eval_env = eval_env.clone();

            let validate_request = req.clone();
            rhai_engine.register_fn(sub_policy_name.clone().as_str(), move || {
                // TODO: get rid of the `unwrap()`
                let response = Self::validate_individual_policy(
                    rhai_eval_env.clone(),
                    &sub_policy_id,
                    &validate_request,
                )
                .unwrap();

                if response.patch.is_some() {
                    // mutation is not allowed inside of group policies
                    return false;
                }
                response.allowed
            });
        }

        let rhai_engine = rhai_engine;

        // TODO: get rid of the `unwrap()`
        let allowed = rhai_engine.eval::<bool>(expression.as_str()).unwrap();

        let status = if allowed {
            None
        } else {
            Some(AdmissionResponseStatus {
                message: Some(message),
                code: None,
            })
        };

        //TODO: capture the sub-policy failure messages and include them in the response as
        //warnings

        Ok(AdmissionResponse {
            uid: req.uid().to_string(),
            allowed,
            patch_type: None,
            patch: None,
            status,
            audit_annotations: None,
            warnings: None,
        })
    }
}

fn create_wasmtime_module(
    policy_id: &str,
    engine: &wasmtime::Engine,
    precompiled_policy: &PrecompiledPolicy,
) -> Result<wasmtime::Module> {
    // See `wasmtime::Module::deserialize` to know why this method is `unsafe`.
    // However, in our context, nothing bad will happen because we have
    // full control of the precompiled module. This is generated by the
    // WorkerPool thread
    unsafe { wasmtime::Module::deserialize(engine, &precompiled_policy.precompiled_module) }
        .map_err(|e| {
            EvaluationError::WebAssemblyError(format!(
                "could not rehydrate wasmtime::Module {policy_id}: {e:?}"
            ))
        })
}

/// Internal function, takes care of creating the `PolicyEvaluator` instance for the given policy
fn create_policy_evaluator_pre(
    engine: &wasmtime::Engine,
    module: &wasmtime::Module,
    mode: PolicyExecutionMode,
    policy_evaluation_limit_seconds: Option<u64>,
) -> Result<PolicyEvaluatorPre> {
    let mut policy_evaluator_builder = PolicyEvaluatorBuilder::new()
        .engine(engine.to_owned())
        .policy_module(module.to_owned())
        .execution_mode(mode);

    if let Some(limit) = policy_evaluation_limit_seconds {
        policy_evaluator_builder =
            policy_evaluator_builder.enable_epoch_interruptions(limit, limit);
    }

    policy_evaluator_builder.build_pre().map_err(|e| {
        EvaluationError::WebAssemblyError(format!("cannot build PolicyEvaluatorPre {e}"))
    })
}

#[cfg(test)]
mod tests {
    use policy_evaluator::policy_evaluator::ValidateRequest;
    use rstest::*;
    use std::collections::BTreeSet;

    use super::*;
    use crate::config::Policy;
    use crate::test_utils::build_admission_review_request;

    fn build_evaluation_environment() -> Result<EvaluationEnvironment> {
        let engine = wasmtime::Engine::default();
        let policy_ids = vec!["policy_1", "policy_2"];
        let module = wasmtime::Module::new(&engine, "(module (func))")
            .expect("should be able to build the smallest wasm module ever");
        let (callback_handler_tx, _) = mpsc::channel(10);

        let precompiled_policy = PrecompiledPolicy {
            precompiled_module: module.serialize().unwrap(),
            execution_mode: policy_evaluator::policy_evaluator::PolicyExecutionMode::Wasi,
            digest: "unique-digest".to_string(),
        };

        let mut policies: HashMap<String, crate::config::Policy> = HashMap::new();
        let mut precompiled_policies: PrecompiledPolicies = PrecompiledPolicies::new();

        for policy_id in &policy_ids {
            let policy_url = format!("file:///tmp/{policy_id}.wasm");
            policies.insert(
                policy_id.to_string(),
                Policy::Individual {
                    url: policy_url.clone(),
                    policy_mode: PolicyMode::Protect,
                    allowed_to_mutate: None,
                    settings: None,
                    context_aware_resources: BTreeSet::new(),
                },
            );
            precompiled_policies.insert(policy_url, Ok(precompiled_policy.clone()));
        }

        EvaluationEnvironment::new(
            &engine,
            &policies,
            &precompiled_policies,
            None,
            callback_handler_tx,
            true,
        )
    }

    fn build_validator() -> Result<Validator> {
        Ok(Validator {
            always_accept_admission_reviews_on_namespace: None,
            evaluation_environment: Arc::new(build_evaluation_environment()?),
        })
    }

    #[rstest]
    #[case("policy_not_defined", true)]
    #[case("policy_1", false)]
    fn return_policy_not_found_error(#[case] policy_id: &str, #[case] expect_error: bool) {
        let validator = build_validator().unwrap();
        let evaluation_environment = validator.evaluation_environment.clone();
        let validate_request =
            ValidateRequest::AdmissionRequest(build_admission_review_request().request);

        if expect_error {
            assert!(matches!(
                validator.get_policy_mode(policy_id),
                Err(EvaluationError::PolicyNotFound(_))
            ));
            assert!(matches!(
                validator.get_policy_allowed_to_mutate(policy_id),
                Err(EvaluationError::PolicyNotFound(_))
            ));
            assert!(matches!(
                evaluation_environment.get_policy_settings(policy_id),
                Err(EvaluationError::PolicyNotFound(_))
            ));
            assert!(matches!(
                validator.validate(policy_id, &validate_request),
                Err(EvaluationError::PolicyNotFound(_))
            ));
        } else {
            assert!(validator.get_policy_mode(policy_id).is_ok());
            assert!(validator.get_policy_allowed_to_mutate(policy_id).is_ok());
            assert!(evaluation_environment
                .get_policy_settings(policy_id)
                .is_ok());
            // note: we do not test `validate` with a known policy because this would
            // cause another error. The test policy we're using is just an empty Wasm
            // module
        }
    }

    /// Given to identical wasm modules, only one instance of PolicyEvaluator is going to be
    /// created
    #[test]
    fn avoid_duplicated_instaces_of_policy_evaluator() {
        let evaluation_environment = build_evaluation_environment().unwrap();

        assert_eq!(
            evaluation_environment
                .module_digest_to_policy_evaluator_pre
                .len(),
            1
        );
    }

    #[test]
    fn validate_policy_with_initialization_error() {
        let mut evaluation_environment = build_evaluation_environment().unwrap();
        let policy_id = "policy_3";
        evaluation_environment
            .policy_initialization_errors
            .insert(policy_id.to_string(), "error".to_string());
        let validator = Validator {
            always_accept_admission_reviews_on_namespace: None,
            evaluation_environment: Arc::new(evaluation_environment),
        };

        let validate_request =
            ValidateRequest::AdmissionRequest(build_admission_review_request().request);
        assert!(matches!(
            validator.validate(policy_id, &validate_request).unwrap_err(),
            EvaluationError::PolicyInitialization(error) if error == "error"
        ));
    }
}
