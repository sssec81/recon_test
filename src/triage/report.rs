use crate::triage::model::{EndpointRecord, Finding, ResponseAnomaly, ReviewQueue};
use std::fs;
use std::path::{Path, PathBuf};

pub fn write_review(
    queue: &mut ReviewQueue,
    output_root: &Path,
    endpoints: &[EndpointRecord],
    anomalies: &[ResponseAnomaly],
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let run_dir = output_root.join(queue.scan_id.to_string());
    fs::create_dir_all(&run_dir)?;
    for (index, finding) in queue.findings.iter_mut().enumerate() {
        let evidence_dir = run_dir
            .join("evidence")
            .join(format!("finding-{:03}", index + 1));
        fs::create_dir_all(&evidence_dir)?;
        write_json(&evidence_dir.join("baseline.json"), &finding.baseline)?;
        for (repeat_index, repeat) in finding.repeats.iter().enumerate() {
            write_json(
                &evidence_dir.join(format!("repeat-{:02}.json", repeat_index + 1)),
                repeat,
            )?;
        }
        if let Some(control) = &finding.control {
            write_json(&evidence_dir.join("control.json"), control)?;
        }
        finding.evidence_dir = Some(evidence_dir.to_string_lossy().to_string());
        write_json(&evidence_dir.join("metadata.json"), finding)?;
    }
    write_json(&run_dir.join("review.json"), queue)?;
    write_json(&run_dir.join("endpoints.json"), &endpoints)?;
    write_json(&run_dir.join("anomalies.json"), &anomalies)?;
    fs::write(run_dir.join("review.md"), render_markdown(queue))?;
    Ok(run_dir)
}

fn write_json(
    path: &Path,
    value: &impl serde::Serialize,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn render_markdown(queue: &ReviewQueue) -> String {
    let mut output = format!(
        "# Recon review queue\n\nScan: `{}`\n\nPages crawled: {} · Requests: {} · Endpoints: {} · Response anomalies: {} · Candidates: {} · Suppressed: {} · Budget exhausted: {}\n\n",
        queue.scan_id,
        queue.pages_crawled,
        queue.requests_sent,
        queue.endpoints_discovered,
        queue.response_anomalies,
        queue.candidates_found,
        queue.findings_suppressed,
        queue.budget_exhausted,
    );
    if queue.findings.is_empty() {
        output.push_str("No evidence-backed candidates reached the review threshold.\n");
    }
    for (index, finding) in queue.findings.iter().enumerate() {
        append_finding(&mut output, index + 1, finding);
    }
    output
}

fn append_finding(output: &mut String, index: usize, finding: &Finding) {
    output.push_str(&format!(
        "## {index}. {} ({:?})\n\n**Endpoint:** `{}`\n\n**Category:** `{}`\n\n**Why flagged:** {}\n\n**False-positive considerations:** {}\n\n**Manual validation:** {}\n\n",
        finding.title, finding.confidence, finding.endpoint, finding.category, finding.reason,
        finding.false_positive_notes, finding.manual_validation,
    ));
    output.push_str(&format!(
        "**Evidence:** baseline status {:?}, {} repeat(s), control {}. Saved at `{}`.\n\n",
        finding.baseline.status,
        finding.repeats.len(),
        if finding.control.is_some() {
            "recorded"
        } else {
            "not run"
        },
        finding.evidence_dir.as_deref().unwrap_or(""),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    #[test]
    fn empty_queue_renders_clearly() {
        let queue = ReviewQueue {
            scan_id: Uuid::new_v4(),
            pages_crawled: 0,
            requests_sent: 0,
            budget_exhausted: false,
            candidates_found: 0,
            findings_suppressed: 0,
            findings: vec![],
            endpoints_discovered: 0,
            response_anomalies: 0,
        };
        assert!(render_markdown(&queue).contains("No evidence-backed candidates"));
    }
}
