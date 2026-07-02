use crate::{
    chat::{Tool, ToolChoice},
    error::LLMError,
    LLMProvider,
};

use crate::builder::build::helpers;
use crate::builder::state::BuilderState;

#[cfg(feature = "deepseek")]
pub(super) fn build_deepseek_compat(
    state: &mut BuilderState,
    tools: Option<Vec<Tool>>,
    tool_choice: Option<ToolChoice>,
) -> Result<Box<dyn LLMProvider>, LLMError> {
    let api_key = helpers::require_api_key(state, "DeepSeek")?;
    let timeout = helpers::timeout_or_default(state);
    let provider = crate::backends::deepseek::DeepSeekCompat::with_config(
        api_key,
        state.base_url.take(),
        state.model.take(),
        state.max_tokens,
        state.temperature,
        timeout,
        state.system.take(),
        state.top_p,
        state.top_k,
        tools,
        tool_choice,
        state.extra_body.take(),
        None,
        None,
        state.reasoning_effort.take(),
        state.json_schema.take(),
        state.enable_parallel_tool_use,
        state.normalize_response,
    );
    Ok(Box::new(provider))
}

#[cfg(not(feature = "deepseek"))]
pub(super) fn build_deepseek_compat(
    _state: &mut BuilderState,
    _tools: Option<Vec<Tool>>,
    _tool_choice: Option<ToolChoice>,
) -> Result<Box<dyn LLMProvider>, LLMError> {
    Err(LLMError::InvalidRequest(
        "DeepSeek feature not enabled".to_string(),
    ))
}
