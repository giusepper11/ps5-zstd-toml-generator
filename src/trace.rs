//! Offline trace evidence. Observations never authorize profile selection.
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceError(pub String);
impl std::fmt::Display for TraceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for TraceError {}

#[derive(Debug, Clone)]
pub struct Trace {
    pub title_id: String,
    pub content_version: String,
    pub executable_sha256: String,
    pub runtime_sha256: String,
    pub certificate_sha256: String,
    pub scenario: String,
    pub dropped_events: u64,
    pub hook_ready: bool,
    pub events_before_hook: usize,
    pub events: usize,
    pub accepted: usize,
    pub completed: usize,
    pub failed: usize,
    pub unresolved: usize,
    pub pending: usize,
    pub observed_paths: BTreeSet<String>,
    pub completed_io_paths: BTreeSet<String>,
    pub unsupported_api_paths: BTreeSet<String>,
}

fn fail(line: usize, message: &str) -> TraceError {
    TraceError(format!("line {line}: {message}"))
}
fn hash_ok(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}
fn path_ok(s: &str) -> bool {
    s.strip_prefix("/app0/").is_some_and(|tail| {
        !tail.is_empty()
            && !tail.contains('\\')
            && !tail
                .split('/')
                .any(|p| p == "." || p == ".." || p.is_empty())
    })
}
fn field<'a>(map: &'a BTreeMap<&str, &str>, key: &str) -> Result<&'a str, TraceError> {
    map.get(key)
        .copied()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| TraceError(format!("missing metadata: {key}")))
}

impl Trace {
    pub fn parse(input: &str) -> Result<Self, TraceError> {
        let mut meta = BTreeMap::new();
        let mut rows = Vec::new();
        for (i, line) in input.lines().enumerate() {
            let n = i + 1;
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let c: Vec<_> = line.split('\t').collect();
            if c.iter()
                .any(|s| s.is_empty() || s.chars().any(char::is_control))
            {
                return Err(fail(n, "empty field or control character"));
            }
            if c.first() == Some(&"meta") {
                if c.len() == 3
                    && !matches!(
                        c[1],
                        "schema"
                            | "title_id"
                            | "content_version"
                            | "executable_sha256"
                            | "runtime_sha256"
                            | "certificate_sha256"
                            | "scenario"
                            | "dropped_events"
                    )
                {
                    return Err(fail(n, "unknown metadata"));
                }
                if !rows.is_empty()
                    || c.len() != 3
                    || c[1].is_empty()
                    || c[2].is_empty()
                    || meta.insert(c[1], c[2]).is_some()
                {
                    return Err(fail(n, "invalid or duplicate metadata"));
                }
            } else if c.first() == Some(&"event") {
                if c.len() != 8 {
                    return Err(fail(n, "event needs 8 fields"));
                }
                rows.push((n, c));
            } else {
                return Err(fail(n, "unknown record"));
            }
        }
        if field(&meta, "schema")? != "ps5-io-trace-v1" {
            return Err(TraceError("unsupported trace schema".into()));
        }
        let title = field(&meta, "title_id")?;
        let version = field(&meta, "content_version")?;
        let exe = field(&meta, "executable_sha256")?;
        let runtime = field(&meta, "runtime_sha256")?;
        let certificate = field(&meta, "certificate_sha256")?;
        let scenario = field(&meta, "scenario")?;
        if !hash_ok(exe) || !hash_ok(runtime) || !hash_ok(certificate) {
            return Err(TraceError(
                "identity hashes must be 64 hex characters".into(),
            ));
        }
        let dropped = field(&meta, "dropped_events")?
            .parse()
            .map_err(|_| TraceError("invalid dropped_events".into()))?;
        let mut result = Trace {
            title_id: title.into(),
            content_version: version.into(),
            executable_sha256: exe.into(),
            runtime_sha256: runtime.into(),
            certificate_sha256: certificate.into(),
            scenario: scenario.into(),
            dropped_events: dropped,
            hook_ready: false,
            events_before_hook: 0,
            events: 0,
            accepted: 0,
            completed: 0,
            failed: 0,
            unresolved: 0,
            pending: 0,
            observed_paths: BTreeSet::new(),
            completed_io_paths: BTreeSet::new(),
            unsupported_api_paths: BTreeSet::new(),
        };
        let mut last = None;
        let mut fds = BTreeMap::<String, (u64, String)>::new();
        let mut generations = BTreeMap::<String, u64>::new();
        let mut requests = BTreeMap::<String, (String, Option<String>)>::new();
        for (n, c) in rows {
            let seq: u64 = c[1].parse().map_err(|_| fail(n, "invalid sequence"))?;
            if last.is_some_and(|v| seq <= v) {
                return Err(fail(n, "sequence must increase"));
            }
            last = Some(seq);
            let (op, fd, request, path, state, detail) = (c[2], c[3], c[4], c[5], c[6], c[7]);
            if path != "-" && !path_ok(path) {
                return Err(fail(n, "path must be an absolute /app0/ path"));
            }
            if detail.is_empty() {
                return Err(fail(n, "empty detail; use -"));
            }
            if !matches!(
                op,
                "open" | "read" | "apr" | "aio" | "map" | "close" | "hook_ready"
            ) || !matches!(state, "accepted" | "completed" | "failed")
            {
                return Err(fail(n, "unknown operation or state"));
            }
            if op != "hook_ready" && !result.hook_ready {
                result.events_before_hook += 1;
            }
            if op == "hook_ready" {
                if fd != "-" || request != "-" || path != "-" || state != "completed" {
                    return Err(fail(n, "invalid hook_ready"));
                }
                result.hook_ready = true;
            }
            result.events += 1;
            match state {
                "accepted" => result.accepted += 1,
                "completed" => result.completed += 1,
                _ => result.failed += 1,
            }
            let mut resolved = if path != "-" {
                Some(path.to_owned())
            } else {
                fds.get(fd).map(|(_, p)| p.clone())
            };
            if op == "open" && state == "completed" {
                if fd == "-" || path == "-" {
                    return Err(fail(n, "completed open requires fd and path"));
                }
                let generation = generations.entry(fd.to_owned()).or_insert(0);
                *generation += 1;
                if fds
                    .insert(fd.to_owned(), (*generation, path.to_owned()))
                    .is_some()
                {
                    result.unresolved += 1;
                }
            }
            if request != "-" && state == "accepted" {
                if requests
                    .insert(request.to_owned(), (op.to_owned(), resolved.clone()))
                    .is_some()
                {
                    return Err(fail(n, "request already pending"));
                }
            } else if request != "-" && state != "accepted" {
                if let Some((saved_op, saved)) = requests.remove(request) {
                    if path != "-" && saved.as_deref().is_some_and(|p| p != path) {
                        result.unresolved += 1;
                    }
                    resolved = if saved_op == op { saved } else { None };
                } else {
                    resolved = None;
                }
            }
            if matches!(op, "read" | "apr" | "aio" | "map") && resolved.is_none() {
                result.unresolved += 1;
            }
            if op == "aio" {
                if let Some(p) = resolved.as_ref() {
                    result.unsupported_api_paths.insert(p.clone());
                } else if path != "-" {
                    result.unsupported_api_paths.insert(path.to_owned());
                }
            }
            if let Some(p) = resolved {
                if state == "completed" && matches!(op, "open" | "read" | "apr" | "aio" | "map") {
                    if op != "open" {
                        result.completed_io_paths.insert(p.clone());
                    }
                    result.observed_paths.insert(p);
                }
            }
            if op == "close" && state == "completed" && fds.remove(fd).is_none() {
                result.unresolved += 1;
            }
        }
        result.pending = requests.len();
        Ok(result)
    }

    pub fn bind_certificate(&self, certificate_text: &str) -> Result<(), TraceError> {
        crate::certificate::Certificate::parse(certificate_text)
            .map_err(|e| TraceError(format!("invalid certificate: {e}")))?;
        let digest =
            crate::certificate::hex(&crate::certificate::digest(certificate_text.as_bytes()));
        if !digest.eq_ignore_ascii_case(&self.certificate_sha256) {
            return Err(TraceError("trace certificate hash mismatch".into()));
        }
        Ok(())
    }

    pub fn report(&self) -> String {
        let mut out = String::new();
        writeln!(
            out,
            "Declared identity (not verified against certificate or dump): {} {} | scenario: {}",
            self.title_id, self.content_version, self.scenario
        )
        .unwrap();
        writeln!(
            out,
            "Declared executable SHA-256: {} | declared runtime SHA-256: {}",
            self.executable_sha256, self.runtime_sha256
        )
        .unwrap();
        writeln!(out, "Certificate text SHA-256: {}", self.certificate_sha256).unwrap();
        out.push_str("The binding checks certificate text and version only; it does not authenticate trace origin or verify the certificate against the dump.\n");
        writeln!(out, "Events: {}; accepted: {}; completed: {}; failed: {}; pending requests: {}; unresolved correlations: {}.", self.events, self.accepted, self.completed, self.failed, self.pending, self.unresolved).unwrap();
        writeln!(
            out,
            "Hook ready: {}; events before hook: {}; dropped events: {}.",
            self.hook_ready, self.events_before_hook, self.dropped_events
        )
        .unwrap();
        writeln!(
            out,
            "Completed observations ({} paths):",
            self.observed_paths.len()
        )
        .unwrap();
        for path in &self.observed_paths {
            writeln!(out, "  {path}").unwrap();
        }
        writeln!(
            out,
            "Completed read/APR/AIO/map paths ({}):",
            self.completed_io_paths.len()
        )
        .unwrap();
        for path in &self.completed_io_paths {
            writeln!(out, "  {path}").unwrap();
        }
        writeln!(
            out,
            "AIO-associated paths ({}):",
            self.unsupported_api_paths.len()
        )
        .unwrap();
        for path in &self.unsupported_api_paths {
            writeln!(out, "  {path}").unwrap();
        }
        out.push_str("AIO is a risk for packed files on ampr-emu-ng 0.3.2; this trace alone does not establish runtime support or interception. Failed and accepted events are included.\n");
        out.push_str("Coverage is limited to recorded scenarios and hooks. Absence is not evidence of no access; observations do not authorize packing.\n");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn metadata() -> String {
        format!("meta\tschema\tps5-io-trace-v1\nmeta\ttitle_id\tPPSA12345\nmeta\tcontent_version\t01.000.000\nmeta\texecutable_sha256\t{}\nmeta\truntime_sha256\t{}\nmeta\tcertificate_sha256\t{}\nmeta\tscenario\tboot\nmeta\tdropped_events\t2\n", "a".repeat(64), "b".repeat(64), "c".repeat(64))
    }
    #[test]
    fn correlates_pending_request_before_fd_reuse() {
        let input = metadata() + "event\t1\thook_ready\t-\t-\t-\tcompleted\t-\nevent\t2\topen\t7\t-\t/app0/a\tcompleted\t-\nevent\t3\taio\t7\tr1\t-\taccepted\t-\nevent\t4\tclose\t7\t-\t-\tcompleted\t-\nevent\t5\topen\t7\t-\t/app0/b\tcompleted\t-\nevent\t6\taio\t7\tr1\t-\tcompleted\t-\n";
        let t = Trace::parse(&input).unwrap();
        assert_eq!(t.pending, 0);
        assert_eq!(t.unresolved, 0);
        assert_eq!(t.dropped_events, 2);
        assert!(t.hook_ready);
        assert!(t.observed_paths.contains("/app0/a"));
        assert!(t.observed_paths.contains("/app0/b"));
        assert!(t.completed_io_paths.contains("/app0/a"));
        assert!(!t.completed_io_paths.contains("/app0/b"));
    }
    #[test]
    fn accepted_is_not_completion_and_bad_paths_are_rejected() {
        let input = metadata() + "event\t1\tread\t-\tr1\t/app0/a\taccepted\t-\n";
        let t = Trace::parse(&input).unwrap();
        assert_eq!(t.pending, 1);
        assert!(t.observed_paths.is_empty());
        assert!(Trace::parse(&(metadata() + "event\t1\tread\t-\t-\ta\tcompleted\t-\n")).is_err());
    }
    #[test]
    fn binds_exact_certificate_and_rejects_changes() {
        let cert = format!("ps5-pack-certificate-v1\nanalyzer={}\npolicy=offline-conservative-v1\nforge=0.5.4\nruntime=0.3.2\ncoverage=evidence-ranges-only\ninventory={}\nselection={}\nprofile={}\nrange=61 0 1 {}\n", env!("CARGO_PKG_VERSION"), "0".repeat(64), "0".repeat(64), "0".repeat(64), "0".repeat(64));
        let digest = crate::certificate::hex(&crate::certificate::digest(cert.as_bytes()));
        let trace = Trace::parse(&metadata().replace(&"c".repeat(64), &digest)).unwrap();
        assert!(trace.bind_certificate(&cert).is_ok());
        assert!(trace.bind_certificate(&(cert.clone() + "\n")).is_err());
        assert!(trace.bind_certificate("unknown").is_err());
    }
    #[test]
    fn reports_failed_aio_and_preserves_request_snapshot() {
        let input = metadata() + "event\t1\taio\t-\tr1\t/app0/first\taccepted\t-\nevent\t2\taio\t-\tr1\t/app0/other\tfailed\t-\nevent\t3\taio\t-\t-\t/app0/failure\tfailed\t-\n";
        let trace = Trace::parse(&input).unwrap();
        assert!(trace.unsupported_api_paths.contains("/app0/first"));
        assert!(trace.unsupported_api_paths.contains("/app0/failure"));
        assert!(!trace.unsupported_api_paths.contains("/app0/other"));
        assert_eq!(trace.unresolved, 1);
        assert!(trace.completed_io_paths.is_empty());
    }
}
