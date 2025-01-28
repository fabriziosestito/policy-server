use tokio::sync::Semaphore;

use std::sync::Arc;

use crate::evaluation::SharedEvaluationEnvironment;

pub(crate) struct ApiServerState {
    pub(crate) semaphore: Semaphore,
    pub(crate) evaluation_environment: SharedEvaluationEnvironment,
}
