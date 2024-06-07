use std::collections::HashMap;

use tokio::sync::Semaphore;

use crate::{config::Group, config::Policy, evaluation::EvaluationEnvironment};

pub(crate) struct ApiServerState {
    pub(crate) semaphore: Semaphore,
    pub(crate) evaluation_environment: EvaluationEnvironment,
    pub(crate) groups: HashMap<String, Group>,
    pub(crate) policies: HashMap<String, Policy>,
}
