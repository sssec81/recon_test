use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub enum LlmProvider {
    Ollama {
        url: String,
        model: String,
    },
    Anthropic {
        api_key: String,
        model: String,
        max_tokens: u32,
    },
}

#[derive(Debug, Serialize)]
struct OllamaRequest {
    model: String,
    prompt: String,
    stream: bool,
}

#[derive(Debug, Deserialize)]
struct OllamaResponse {
    response: String,
}

#[derive(Debug, Serialize)]
struct AnthropicMessage {
    role: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct AnthropicRequest {
    model: String,
    max_tokens: u32,
    messages: Vec<AnthropicMessage>,
}

#[derive(Debug, Deserialize)]
struct AnthropicContentBlock {
    #[serde(rename = "type")]
    block_type: String,
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AnthropicResponse {
    content: Vec<AnthropicContentBlock>,
}

async fn analyze_with_ollama(
    client: &Client,
    url: &str,
    model: &str,
    prompt: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let req_body = OllamaRequest {
        model: model.to_string(),
        prompt: prompt.to_string(),
        stream: false,
    };

    let endpoint = format!("{}/api/generate", url.trim_end_matches('/'));
    let response = client.post(&endpoint).json(&req_body).send().await?;

    if !response.status().is_success() {
        return Err(format!("Ollama API returned status {}", response.status()).into());
    }

    let ollama_res: OllamaResponse = response.json().await?;
    Ok(ollama_res.response)
}

async fn analyze_with_anthropic(
    client: &Client,
    api_key: &str,
    model: &str,
    max_tokens: u32,
    prompt: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let req_body = AnthropicRequest {
        model: model.to_string(),
        max_tokens,
        messages: vec![AnthropicMessage {
            role: "user".to_string(),
            content: prompt.to_string(),
        }],
    };

    let response = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&req_body)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let err_text = response.text().await.unwrap_or_default();
        return Err(format!("Anthropic API returned status {}: {}", status, err_text).into());
    }

    let anthropic_res: AnthropicResponse = response.json().await?;
    let mut combined_text = String::new();
    for block in anthropic_res.content {
        if block.block_type == "text"
            && let Some(t) = block.text
        {
            combined_text.push_str(&t);
        }
    }

    if combined_text.is_empty() {
        Ok("No text content returned from Anthropic API.".to_string())
    } else {
        Ok(combined_text)
    }
}

pub async fn generate_text(
    client: &Client,
    provider: &LlmProvider,
    prompt: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    match provider {
        LlmProvider::Ollama { url, model } => analyze_with_ollama(client, url, model, prompt).await,
        LlmProvider::Anthropic {
            api_key,
            model,
            max_tokens,
        } => analyze_with_anthropic(client, api_key, model, *max_tokens, prompt).await,
    }
}
