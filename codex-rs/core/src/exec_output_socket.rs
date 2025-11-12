// <exec-socket-tap>
use std::fmt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use codex_protocol::ConversationId;
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::info;
use tracing::warn;

#[cfg(unix)]
use std::time::Duration;
#[cfg(unix)]
use tokio::io::AsyncWriteExt;
#[cfg(unix)]
use tokio::net::UnixStream;

/// Metadata describing a single exec output payload that will be forwarded to the
/// configured UNIX socket.
#[derive(Debug, Clone)]
pub(crate) struct ExecSocketPayload<'a> {
    pub call_id: &'a str,
    pub session_id: Option<i32>,
    pub exit_code: Option<i32>,
    pub is_final: bool,
    pub output: &'a str,
}

#[derive(Debug)]
pub(crate) struct ExecOutputSocket {
    path: PathBuf,
    #[cfg(unix)]
    stream: Mutex<Option<UnixStream>>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ExecCommandMetadata<'a> {
    pub call_id: &'a str,
    pub command: &'a str,
    pub cwd: &'a Path,
    pub is_user: bool,
}

impl ExecOutputSocket {
    pub(crate) fn new(path: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            #[cfg(unix)]
            stream: Mutex::new(None),
            path,
        })
    }

    pub(crate) async fn send(
        &self,
        payload: &ExecSocketPayload<'_>,
    ) -> Result<(), ExecSocketError> {
        #[cfg(unix)]
        {
            self.send_unix(payload).await?;
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = payload;
            Err(ExecSocketError::UnsupportedPlatform)
        }
    }

    pub(crate) async fn send_command(
        &self,
        metadata: &ExecCommandMetadata<'_>,
    ) -> Result<(), ExecSocketError> {
        #[cfg(unix)]
        {
            let serialized = serialize_command(metadata);
            self.send_bytes_with_retry(serialized.as_bytes()).await?;
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            return Err(ExecSocketError::UnsupportedPlatform);
        }
        Ok(())
    }

    #[cfg(unix)]
    async fn send_unix(&self, payload: &ExecSocketPayload<'_>) -> Result<(), ExecSocketError> {
        let serialized = serialize_payload(payload);
        self.send_bytes_with_retry(serialized.as_bytes()).await
    }

    #[cfg(unix)]
    async fn send_session_config(
        &self,
        session_id: &ConversationId,
    ) -> Result<(), ExecSocketError> {
        let serialized = serialize_session_config(session_id);
        self.send_bytes_with_retry(serialized.as_bytes()).await
    }

    #[cfg(unix)]
    async fn send_bytes_with_retry(&self, data: &[u8]) -> Result<(), ExecSocketError> {
        const MAX_ATTEMPTS: usize = 5;

        let mut last_connect_error: Option<tokio::io::Error> = None;
        let mut last_write_error: Option<tokio::io::Error> = None;

        for attempt in 0..MAX_ATTEMPTS {
            let mut guard = self.stream.lock().await;

            if guard.is_none() {
                match UnixStream::connect(&self.path).await {
                    Ok(stream) => {
                        *guard = Some(stream);
                    }
                    Err(source) => {
                        warn!(
                            path = ?self.path,
                            attempt,
                            ?source,
                            "exec_socket: connect failed"
                        );
                        last_connect_error = Some(source);

                        drop(guard);

                        if attempt == 0 {
                            continue;
                        }

                        if attempt < MAX_ATTEMPTS - 1 {
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                        continue;
                    }
                }
            }

            if let Some(stream) = guard.as_mut() {
                match stream.write_all(data).await {
                    Ok(()) => return Ok(()),
                    Err(source) => {
                        warn!(
                            path = ?self.path,
                            attempt,
                            ?source,
                            "exec_socket: write failed"
                        );
                        *guard = None;
                        last_write_error = Some(source);
                    }
                }
            }

            drop(guard);

            if attempt == 0 {
                continue;
            }

            if attempt < MAX_ATTEMPTS - 1 {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }

        if let Some(source) = last_write_error {
            return Err(ExecSocketError::Write {
                path: self.path.clone(),
                source,
            });
        }

        if let Some(source) = last_connect_error {
            return Err(ExecSocketError::Connect {
                path: self.path.clone(),
                source,
            });
        }

        Err(ExecSocketError::Connect {
            path: self.path.clone(),
            source: tokio::io::Error::other("exec socket retry attempts exhausted"),
        })
    }

    pub(crate) fn path(&self) -> &PathBuf {
        &self.path
    }
}

fn serialize_payload(payload: &ExecSocketPayload<'_>) -> String {
    let mut out = String::with_capacity(payload.output.len() + 128);
    out.push_str("<exec-output");
    push_attr(&mut out, "call-id", payload.call_id);
    if let Some(session_id) = payload.session_id {
        push_attr(&mut out, "session-id", &session_id.to_string());
    }
    if let Some(exit) = payload.exit_code {
        push_attr(&mut out, "exit-code", &exit.to_string());
    }
    if payload.is_final {
        push_attr(&mut out, "final", "true");
    }
    out.push('>');
    escape_xml(payload.output, &mut out);
    out.push_str("</exec-output>\n");
    out
}

fn serialize_session_config(session_id: &ConversationId) -> String {
    let mut out = String::with_capacity(64);
    out.push_str("<config-session>");
    escape_xml(&session_id.to_string(), &mut out);
    out.push_str("</config-session>\n");
    out
}

fn serialize_command(metadata: &ExecCommandMetadata<'_>) -> String {
    let mut out = String::with_capacity(metadata.command.len() + 128);
    out.push_str("<exec-command");
    push_attr(&mut out, "call-id", metadata.call_id);
    let cwd = metadata.cwd.to_string_lossy();
    push_attr(&mut out, "cwd", &cwd);
    if metadata.is_user {
        push_attr(&mut out, "user", "true");
    }
    out.push('>');
    escape_xml(metadata.command, &mut out);
    out.push_str("</exec-command>\n");
    out
}

fn push_attr(out: &mut String, key: &str, value: &str) {
    out.push(' ');
    out.push_str(key);
    out.push_str("=\"");
    escape_attr(value, out);
    out.push('"');
}

fn escape_xml(value: &str, out: &mut String) {
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(ch),
        }
    }
}

fn escape_attr(value: &str, out: &mut String) {
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum ExecSocketError {
    #[cfg(not(unix))]
    #[error("exec socket not supported on this platform")]
    UnsupportedPlatform,
    #[cfg(unix)]
    #[error("failed to connect to exec socket {path:?}: {source}")]
    Connect {
        path: PathBuf,
        source: tokio::io::Error,
    },
    #[cfg(unix)]
    #[error("failed to write to exec socket {path:?}: {source}")]
    Write {
        path: PathBuf,
        source: tokio::io::Error,
    },
}

impl fmt::Display for ExecOutputSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExecOutputSocket({:?})", self.path)
    }
}

pub(crate) async fn forward_session_config_to_socket(
    socket: &Arc<ExecOutputSocket>,
    session_id: &ConversationId,
) {
    if let Err(err) = socket.send_session_config(session_id).await {
        warn!(
            path = ?socket.path(),
            ?err,
            "failed to forward session config to socket"
        );
    }
}

pub(crate) async fn forward_command_to_socket(
    socket: &Arc<ExecOutputSocket>,
    metadata: ExecCommandMetadata<'_>,
) {
    if let Err(err) = socket.send_command(&metadata).await {
        warn!(
            path = ?socket.path(),
            ?err,
            "failed to forward exec command to socket"
        );
    } else {
        info!(
            path = ?socket.path(),
            call_id = metadata.call_id,
            "exec_socket: command forwarded"
        );
    }
}

pub(crate) async fn forward_to_socket(
    socket: &Arc<ExecOutputSocket>,
    payload: ExecSocketPayload<'_>,
) {
    if let Err(err) = socket.send(&payload).await {
        warn!(
            path = ?socket.path(),
            ?err,
            "failed to forward exec output to socket"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn serialize_session_config_wraps_conversation_id() {
        let session_id =
            ConversationId::from_string("019a92af-86ef-7aa1-867c-39b78c63b9ae").unwrap();

        assert_eq!(
            serialize_session_config(&session_id),
            "<config-session>019a92af-86ef-7aa1-867c-39b78c63b9ae</config-session>\n"
        );
    }
}

// </exec-socket-tap>
