use tokio::sync::Semaphore;

use crate::evaluation::Validator;

pub(crate) struct ApiServerState {
    pub(crate) semaphore: Semaphore,
    pub(crate) validator: Validator,
}
