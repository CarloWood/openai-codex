# cw_exec_socket_tap specific instructions

All changes in this branch are sandwiched between <exec-socket-tap> and </exec-socket-tap>.
If you edit code outside such a block then add those tags around the new code lines as well.

## Overview of functionality
- Config: `exec_socket_path = string (path)`. A UNIX socket at that path is opened; the CLI writes session config (session_id, cwd) as XML.
- For each unified exec command, the PTY command is mirrored to the socket as <exec-command>.
- PTY stdout/stderr are truncated/formatted for `max_output_tokens` in the tool response, and that same truncated stream is mirrored as <exec-output>.
