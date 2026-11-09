# PS5 I/O trace schema v1

This is an offline interchange contract for an external recorder. The analyzer does not provide hooks or assert that a runtime emits these events. UTF-8 TSV; fields cannot contain tabs, control characters or newlines. Empty lines and lines beginning `#` are ignored. Metadata precedes events, each key occurs once, and unknown keys are rejected:

```text
meta\tschema\tps5-io-trace-v1
meta\ttitle_id\tPPSA12345
meta\tcontent_version\t01.000.000
meta\texecutable_sha256\t<64 hex digits>
meta\truntime_sha256\t<64 hex digits>
meta\tcertificate_sha256\t<64 hex digits>
meta\tscenario\tCold boot and save load
meta\tdropped_events\t0
```

Above `\t` denotes a literal tab. Identity fields describe the recorded environment; parser syntax checks do not verify the hashes against files. `certificate_sha256` is the SHA-256 of the exact UTF-8 certificate text, including its line endings and final newline. Binding checks this digest and parses the supported certificate version; it does not verify the certificate against a dump or prove the recorder's identity claims. `dropped_events` must be measured by the recorder, not guessed. Scenario describes only exercised activity.

Each event has eight columns: `event`, increasing unsigned sequence, operation, fd, request ID, path, state, detail. Use `-` for absent fields; identifiers are recorder-defined strings. Path, when supplied, is a full normalized `/app0/...` path, with no empty, `.` or `..` component. Operations are `hook_ready`, `open`, `read`, `apr`, `aio`, `map`, `close`; states are `accepted`, `completed`, `failed`. `hook_ready` is `completed` with absent fd, request and path. A completed open requires fd and full path; completed close ends that fd generation. An accepted asynchronous request snapshots its path before fd reuse; a completion/failed event with the same request ID closes it. IDs may be reused only after completion. A request with unknown path remains unresolved. Detail is nonempty free text (or `-`); it is not interpreted as success, error code, API flags, byte count, or proof of interception. Emit separate accepted and completed events only if the recorder actually observed both. Never invent a completion, hook event, failure or drop count.

The report distinguishes accepted/completed/failed, pending and unresolved, hook readiness, pre-hook events, dropped events and completed paths. AIO-associated paths include accepted and failed operations: AIO poses a risk for packed files on runtime 0.3.2, but this trace alone cannot establish interception or runtime support. A completed path does not by itself prove that reads passed through a particular hook or succeeded with all bytes; details are not checked. A completed open is an observation of opening, not reading. Partial coverage, missing events and unknown semantics are risks; absence is not proof of no access. No trace result automatically authorizes a pack selection.
