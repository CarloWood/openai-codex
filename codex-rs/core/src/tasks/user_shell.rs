use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use codex_async_utils::CancelErr;
use codex_async_utils::OrCancelExt;
use codex_protocol::user_input::UserInput;
use tokio_util::sync::CancellationToken;
use tracing::error;
// <exec-socket-tap>
use tracing::debug;
use tracing::info;
// </exec-socket-tap>
use uuid::Uuid;

use crate::codex::TurnContext;
use crate::exec::ExecToolCallOutput;
use crate::exec::SandboxType;
use crate::exec::StdoutStream;
use crate::exec::StreamOutput;
use crate::exec::execute_exec_env;
use crate::exec_env::create_env;
// <exec-socket-tap> forward user shell output to optional exec socket
use crate::exec_output_socket::ExecCommandMetadata;
use crate::exec_output_socket::ExecOutputSocket;
use crate::exec_output_socket::ExecSocketPayload;
use crate::exec_output_socket::forward_command_to_socket;
use crate::exec_output_socket::forward_to_socket;
// </exec-socket-tap>
use crate::parse_command::parse_command;
use crate::protocol::EventMsg;
use crate::protocol::ExecCommandBeginEvent;
use crate::protocol::ExecCommandEndEvent;
use crate::protocol::ExecCommandSource;
use crate::protocol::SandboxPolicy;
use crate::protocol::TaskStartedEvent;
use crate::sandboxing::ExecEnv;
use crate::sandboxing::SandboxPermissions;
use crate::state::TaskKind;
use crate::tools::format_exec_output_str;
use crate::user_shell_command::user_shell_command_record_item;

use super::SessionTask;
use super::SessionTaskContext;

const USER_SHELL_TIMEOUT_MS: u64 = 60 * 60 * 1000; // 1 hour

#[derive(Clone)]
pub(crate) struct UserShellCommandTask {
    command: String,
}

// <exec-socket-tap> send user shell exec output chunks to configured socket
async fn forward_exec_socket_output(
    exec_socket: &Option<Arc<ExecOutputSocket>>,
    call_id: &str,
    exit_code: i32,
    output: &str,
) {
    if let Some(socket) = exec_socket.as_ref() {
        let payload = ExecSocketPayload {
            call_id,
            session_id: None,
            exit_code: Some(exit_code),
            is_final: true,
            output,
        };
        forward_to_socket(socket, payload).await;
    }
}
// </exec-socket-tap>

impl UserShellCommandTask {
    pub(crate) fn new(command: String) -> Self {
        Self { command }
    }
}

#[async_trait]
impl SessionTask for UserShellCommandTask {
    fn kind(&self) -> TaskKind {
        TaskKind::Regular
    }

    async fn run(
        self: Arc<Self>,
        session: Arc<SessionTaskContext>,
        turn_context: Arc<TurnContext>,
        _input: Vec<UserInput>,
        cancellation_token: CancellationToken,
    ) -> Option<String> {
        let event = EventMsg::TaskStarted(TaskStartedEvent {
            model_context_window: turn_context.client.get_model_context_window(),
        });
        let session = session.clone_session();
        session.send_event(turn_context.as_ref(), event).await;

        // Execute the user's script under their default shell when known; this
        // allows commands that use shell features (pipes, &&, redirects, etc.).
        // We do not source rc files or otherwise reformat the script.
        let use_login_shell = true;
        let command = session
            .user_shell()
            .derive_exec_args(&self.command, use_login_shell);

        let call_id = Uuid::new_v4().to_string();
        let raw_command = self.command.clone();
        let cwd = turn_context.cwd.clone();
        // <exec-socket-tap>
        let exec_socket = turn_context.exec_output_socket();

        if let Some(socket) = exec_socket.as_ref() {
            let metadata = ExecCommandMetadata {
                call_id: &call_id,
                command: &raw_command,
                is_user: true,
            };

            info!(?metadata, "user_shell: forwarding exec command to socket");
            debug!(?metadata, "user_shell: forwarding exec command to socket");
            forward_command_to_socket(socket, metadata).await;
        }
        // </exec-socket-tap>

        let parsed_cmd = parse_command(&command);
        session
            .send_event(
                turn_context.as_ref(),
                EventMsg::ExecCommandBegin(ExecCommandBeginEvent {
                    call_id: call_id.clone(),
                    process_id: None,
                    turn_id: turn_context.sub_id.clone(),
                    command: command.clone(),
                    cwd: cwd.clone(),
                    parsed_cmd: parsed_cmd.clone(),
                    source: ExecCommandSource::UserShell,
                    interaction_input: None,
                }),
            )
            .await;

        let exec_env = ExecEnv {
            command: command.clone(),
            cwd: cwd.clone(),
            env: create_env(&turn_context.shell_environment_policy),
            // TODO(zhao-oai): Now that we have ExecExpiration::Cancellation, we
            // should use that instead of an "arbitrarily large" timeout here.
            expiration: USER_SHELL_TIMEOUT_MS.into(),
            sandbox: SandboxType::None,
            sandbox_permissions: SandboxPermissions::UseDefault,
            justification: None,
            arg0: None,
        };

        let stdout_stream = Some(StdoutStream {
            sub_id: turn_context.sub_id.clone(),
            call_id: call_id.clone(),
            tx_event: session.get_tx_event(),
        });

        let sandbox_policy = SandboxPolicy::DangerFullAccess;
        // <exec-socket-tap> log exec command heading into exec_env for socket tap visibility
        info!(
            "user_shell: calling execute_exec_env with command {:?}",
            exec_env.command
        );
        // </exec-socket-tap>
        let exec_result = execute_exec_env(exec_env, &sandbox_policy, stdout_stream)
            .or_cancel(&cancellation_token)
            .await;

        match exec_result {
            Err(CancelErr::Cancelled) => {
                let aborted_message = "command aborted by user".to_string();
                let exec_output = ExecToolCallOutput {
                    exit_code: -1,
                    stdout: StreamOutput::new(String::new()),
                    stderr: StreamOutput::new(aborted_message.clone()),
                    aggregated_output: StreamOutput::new(aborted_message.clone()),
                    duration: Duration::ZERO,
                    timed_out: false,
                };
                let output_items = [user_shell_command_record_item(
                    &raw_command,
                    &exec_output,
                    &turn_context,
                )];
                session
                    .record_conversation_items(turn_context.as_ref(), &output_items)
                    .await;
                // <exec-socket-tap>
                forward_exec_socket_output(&exec_socket, &call_id, -1, &aborted_message).await;
                // </exec-socket-tap>
                session
                    .send_event(
                        turn_context.as_ref(),
                        EventMsg::ExecCommandEnd(ExecCommandEndEvent {
                            call_id,
                            process_id: None,
                            turn_id: turn_context.sub_id.clone(),
                            command: command.clone(),
                            cwd: cwd.clone(),
                            parsed_cmd: parsed_cmd.clone(),
                            source: ExecCommandSource::UserShell,
                            interaction_input: None,
                            stdout: String::new(),
                            stderr: aborted_message.clone(),
                            aggregated_output: aborted_message.clone(),
                            exit_code: -1,
                            duration: Duration::ZERO,
                            formatted_output: aborted_message,
                        }),
                    )
                    .await;
            }
            Ok(Ok(output)) => {
                // <exec-socket-tap> forward full aggregated output to the exec socket before recording events
                let aggregated_output = output.aggregated_output.text.clone();
                forward_exec_socket_output(
                    &exec_socket,
                    &call_id,
                    output.exit_code,
                    &aggregated_output,
                )
                .await;
                // </exec-socket-tap>
                session
                    .send_event(
                        turn_context.as_ref(),
                        EventMsg::ExecCommandEnd(ExecCommandEndEvent {
                            // <exec-socket-tap> : remove ': call_id.clone()'
                            call_id,
                            // </exec-socket-tap>
                            process_id: None,
                            turn_id: turn_context.sub_id.clone(),
                            command: command.clone(),
                            cwd: cwd.clone(),
                            parsed_cmd: parsed_cmd.clone(),
                            source: ExecCommandSource::UserShell,
                            interaction_input: None,
                            stdout: output.stdout.text.clone(),
                            stderr: output.stderr.text.clone(),
                            // <exec-socket-tap> reuse aggregated_output captured for socket forwarding
                            aggregated_output,
                            // </exec-socket-tap>
                            exit_code: output.exit_code,
                            duration: output.duration,
                            formatted_output: format_exec_output_str(
                                &output,
                                turn_context.truncation_policy,
                            ),
                        }),
                    )
                    .await;

                let output_items = [user_shell_command_record_item(
                    &raw_command,
                    &output,
                    &turn_context,
                )];
                session
                    .record_conversation_items(turn_context.as_ref(), &output_items)
                    .await;
            }
            Ok(Err(err)) => {
                error!("user shell command failed: {err:?}");
                let message = format!("execution error: {err:?}");
                let exec_output = ExecToolCallOutput {
                    exit_code: -1,
                    stdout: StreamOutput::new(String::new()),
                    stderr: StreamOutput::new(message.clone()),
                    aggregated_output: StreamOutput::new(message.clone()),
                    duration: Duration::ZERO,
                    timed_out: false,
                };
                // <exec-socket-tap> forward error output to exec socket and reuse captured aggregate
                let aggregated_output = exec_output.aggregated_output.text.clone();
                forward_exec_socket_output(
                    &exec_socket,
                    &call_id,
                    exec_output.exit_code,
                    &aggregated_output,
                )
                .await;
                // </exec-socket-tap>
                session
                    .send_event(
                        turn_context.as_ref(),
                        EventMsg::ExecCommandEnd(ExecCommandEndEvent {
                            call_id,
                            process_id: None,
                            turn_id: turn_context.sub_id.clone(),
                            command,
                            cwd,
                            parsed_cmd,
                            source: ExecCommandSource::UserShell,
                            interaction_input: None,
                            stdout: exec_output.stdout.text.clone(),
                            stderr: exec_output.stderr.text.clone(),
                            // <exec-socket-tap> reuse aggregated output string sent to socket
                            aggregated_output,
                            // </exec-socket-tap>
                            exit_code: exec_output.exit_code,
                            duration: exec_output.duration,
                            formatted_output: format_exec_output_str(
                                &exec_output,
                                turn_context.truncation_policy,
                            ),
                        }),
                    )
                    .await;
                let output_items = [user_shell_command_record_item(
                    &raw_command,
                    &exec_output,
                    &turn_context,
                )];
                session
                    .record_conversation_items(turn_context.as_ref(), &output_items)
                    .await;
            }
        }
        None
    }
}
