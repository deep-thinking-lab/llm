use thiserror::Error;

/// Error types that can occur when interacting with LLM providers.
#[derive(Debug, Error)]
pub enum LLMError {
    /// HTTP request/response errors
    #[error("HTTP error: {0}")]
    HttpError(String),
    /// Authentication and authorization errors
    #[error("Auth error: {0}")]
    AuthError(String),
    /// Invalid request parameters or format
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    /// Errors returned by the LLM provider
    #[error("Provider error: {0}")]
    ProviderError(String),
    /// API response parsing or format error
    #[error("Response format error: {message}. Raw response: {raw_response}")]
    ResponseFormatError {
        message: String,
        raw_response: String,
    },
    /// Generic error
    #[error("Generic error: {0}")]
    Generic(String),
    /// JSON serialization/deserialization errors
    #[error("JSON parse error: {0}")]
    JsonError(String),
    /// Tool configuration error
    #[error("Tool configuration error: {0}")]
    ToolConfigError(String),
    /// Retry attempts exceeded
    #[error("Retry attempts exceeded after {attempts} tries: {last_error}")]
    RetryExceeded { attempts: usize, last_error: String },
    /// A message type (Image, Pdf, etc.) is not supported by this backend or
    /// operation path. Distinct from `InvalidRequest` so callers can detect
    /// and handle capability gaps explicitly.
    #[error("Unsupported message type: {0}")]
    UnsupportedMessageType(String),
    /// A backend does not implement a particular operation (e.g. completion,
    /// chat-with-tools). Surfaced instead of panicking so the call returns a
    /// recoverable error.
    #[error("{backend} does not implement {operation}")]
    BackendNotImplemented {
        backend: &'static str,
        operation: &'static str,
    },
}

/// Converts reqwest HTTP errors into LlmErrors
impl From<reqwest::Error> for LLMError {
    fn from(err: reqwest::Error) -> Self {
        LLMError::HttpError(err.to_string())
    }
}

impl From<serde_json::Error> for LLMError {
    fn from(err: serde_json::Error) -> Self {
        LLMError::JsonError(format!(
            "{} at line {} column {}",
            err,
            err.line(),
            err.column()
        ))
    }
}
