//! Minimal Sigma evaluator for the fields the agent emits. Supports the
//! `selection`/`filter`/`condition` shape with `contains`, `startswith`,
//! `endswith`, `all`, and exact match. Full Sigma (regex, aggregation) is
//! handled by converting rules offline with sigma-rust in v0.3.
use crate::Ctx;
use anyhow::Result;
use serde::Deserialize;
use std::{collections::HashMap, path::Path, sync::Arc};

#[derive(Debug, Deserialize, Clone)]
pub struct Rule {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub level: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub logsource: LogSource,
    pub detection: Detection,
}
#[derive(Debug, Deserialize, Clone)]
pub struct LogSource {
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub product: String,
}
#[derive(Debug, Deserialize, Clone)]
pub struct Detection {
    #[serde(flatten)]
    pub blocks: HashMap<String, serde_yaml_ng::Value>,
    pub condition: String,
}

pub fn load_rules(dir: &Path) -> Result<Arc<Vec<Rule>>> {
    let mut out = vec![];
    if let Ok(rd) = std::fs::read_dir(dir.join("sigma")) {
        for e in rd.flatten() {
            if e.path().extension().map(|x| x == "yml").unwrap_or(false) {
                match serde_yaml_ng::from_str::<Rule>(&std::fs::read_to_string(e.path())?) {
                    Ok(r) => out.push(r),
                    Err(err) => tracing::warn!(file = %e.path().display(), %err, "bad sigma rule"),
                }
            }
        }
    }
    Ok(Arc::new(out))
}

/// Field names: Image, ParentImage, CommandLine, User, TargetObject, Details, ScriptBlockText, LogonType, SourceIp, DestinationPort.
pub fn matches(rule: &Rule, ev: &HashMap<String, String>) -> bool {
    let eval_block = |v: &serde_yaml_ng::Value| -> bool {
        let Some(m) = v.as_mapping() else {
            return false;
        };
        m.iter().all(|(k, val)| {
            let k = k.as_str().unwrap_or("");
            let (field, modifier) = k.split_once('|').unwrap_or((k, ""));
            let Some(actual) = ev.get(field) else {
                return false;
            };
            let a = actual.to_ascii_lowercase();
            let candidates: Vec<String> = match val {
                serde_yaml_ng::Value::Sequence(s) => s
                    .iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_ascii_lowercase()))
                    .collect(),
                other => other
                    .as_str()
                    .map(|s| vec![s.to_ascii_lowercase()])
                    .unwrap_or_default(),
            };
            let test = |c: &str| match modifier {
                "contains" | "contains|all" => a.contains(c),
                "startswith" => a.starts_with(c),
                "endswith" => a.ends_with(c),
                _ => a == c,
            };
            if modifier.ends_with("all") {
                candidates.iter().all(|c| test(c))
            } else {
                candidates.iter().any(|c| test(c))
            }
        })
    };
    let results: HashMap<&str, bool> = rule
        .detection
        .blocks
        .iter()
        .map(|(k, v)| (k.as_str(), eval_block(v)))
        .collect();
    // condition grammar: "selection", "selection and not filter", "sel1 or sel2", "1 of selection*"
    let c = rule.detection.condition.trim();
    if let Some(rest) = c.strip_prefix("1 of ") {
        let p = rest.trim_end_matches('*');
        return results.iter().any(|(k, v)| k.starts_with(p) && *v);
    }
    if let Some(rest) = c.strip_prefix("all of ") {
        let p = rest.trim_end_matches('*');
        return results
            .iter()
            .filter(|(k, _)| k.starts_with(p))
            .all(|(_, v)| *v);
    }
    let mut acc = None::<bool>;
    let mut op = "and";
    let mut toks = c.split_whitespace().peekable();
    while let Some(t) = toks.next() {
        match t {
            "and" | "or" => {
                op = t;
                continue;
            }
            _ => {}
        }
        let (neg, name) = if t == "not" {
            (true, toks.next().unwrap_or(""))
        } else {
            (false, t)
        };
        let v = results.get(name).copied().unwrap_or(false) ^ neg;
        acc = Some(match (acc, op) {
            (None, _) => v,
            (Some(a), "and") => a && v,
            (Some(a), _) => a || v,
        });
    }
    acc.unwrap_or(false)
}

pub async fn evaluate_recent(ctx: Ctx, rules: Arc<Vec<Rule>>) -> Result<()> {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct Ev {
        host_id: String,
        ts_wall_ms: u64,
        kind: String,
        pid: u32,
        image: String,
        user: String,
        detail: String,
        path: String,
        src_ip: String,
        dst_port: u32,
        extra: String,
    }
    let rows = ctx
        .ch
        .query("SELECT host_id, ts_wall_ms, kind, pid, image, user, detail, path, src_ip, dst_port, extra FROM events WHERE kind IN ('process','registry','logon','script') AND ts_recv_ms >= toUnixTimestamp64Milli(now64()) - 25000")
        .fetch_all::<Ev>()
        .await?;
    let mut n = 0;
    for Ev {
        host_id: host,
        ts_wall_ms: ts,
        kind,
        pid,
        image,
        user,
        detail,
        path,
        src_ip,
        dst_port,
        extra,
    } in rows
    {
        let parent = serde_json::from_str::<serde_json::Value>(&extra)
            .ok()
            .and_then(|v| v["parent"].as_str().map(String::from))
            .unwrap_or_default();
        let ev: HashMap<String, String> = [
            ("Image", image.clone()),
            ("ParentImage", parent),
            ("CommandLine", detail.clone()),
            ("User", user.clone()),
            ("TargetObject", path.clone()),
            ("Details", detail.clone()),
            ("ScriptBlockText", detail.clone()),
            ("SourceIp", src_ip),
            ("DestinationPort", dst_port.to_string()),
            ("LogonType", kv(&detail, "type")),
            ("AuthPackage", kv(&detail, "pkg")),
            ("EventID", kv(&detail, "id")),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        for r in rules.iter().filter(|r| {
            r.logsource.category.is_empty() || category_matches(&r.logsource.category, &kind)
        }) {
            if matches(r, &ev) {
                n += 1;
                sqlx::query("INSERT INTO alerts(alert_id, host_id, rule_id, rule, severity, tactic, process, username, ts, status) VALUES(gen_random_uuid()::text,$1,$2,$3,$4,$5,$6,$7,to_timestamp($8/1000.0),'open') ON CONFLICT DO NOTHING")
                    .bind(&host).bind(&r.id).bind(&r.title).bind(if r.level.is_empty() { "medium" } else { &r.level }).bind(r.tags.iter().find(|t| t.starts_with("attack.t")).cloned().unwrap_or_default()).bind(&image).bind(&user).bind(ts as i64).execute(&ctx.pg).await?;
                let _ = pid;
            }
        }
    }
    if n > 0 {
        tracing::info!(alerts = n, "sigma matches");
    }
    Ok(())
}
/// Pull `key=value` tokens out of the flattened logon detail string.
fn kv(detail: &str, key: &str) -> String {
    detail
        .split_whitespace()
        .find_map(|t| t.strip_prefix(&format!("{key}=")).map(str::to_string))
        .unwrap_or_default()
}
fn category_matches(cat: &str, kind: &str) -> bool {
    matches!(
        (cat, kind),
        ("process_creation", "process")
            | ("registry_set" | "registry_event", "registry")
            | ("ps_script", "script")
            | ("logon", "logon")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encoded_powershell_rule() {
        let r: Rule = serde_yaml_ng::from_str(
            r#"
id: t1
title: Encoded PowerShell
level: high
tags: [attack.execution, attack.t1059.001]
logsource: {category: process_creation, product: windows}
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: ['-enc', '-encodedcommand']
  filter:
    ParentImage|endswith: '\ConfigurationManager.exe'
  condition: selection and not filter
"#,
        )
        .unwrap();
        let ev: HashMap<String, String> = [
            (
                "Image",
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            ),
            ("CommandLine", "powershell -EncodedCommand ZQBjAGgAbwA="),
            ("ParentImage", r"C:\Windows\explorer.exe"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        assert!(matches(&r, &ev));
        let mut ev2 = ev.clone();
        ev2.insert(
            "ParentImage".into(),
            r"C:\SCCM\ConfigurationManager.exe".into(),
        );
        assert!(!matches(&r, &ev2));
    }
}
