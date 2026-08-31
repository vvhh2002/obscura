use std::collections::HashMap;
use std::io::Write as _;
use std::path::Path;

use obscura_browser::{
    CaptchaAdapter, CaptchaArtifact, CaptchaExtraction, CaptchaImageRole, CaptchaSourceKind,
};
use sha2::{Digest as _, Sha256};

pub(crate) struct CaptchaOutputSummary {
    pub(crate) discovered: usize,
    pub(crate) groups: usize,
    pub(crate) image_files: usize,
    pub(crate) unresolved_images: usize,
    pub(crate) source_pairs: usize,
    pub(crate) image_pairs: usize,
    pub(crate) evidence_complete: bool,
}

pub(crate) fn write_captcha_outputs(
    extraction: &CaptchaExtraction,
    images_dir: Option<&Path>,
    urls_output: Option<&Path>,
) -> anyhow::Result<CaptchaOutputSummary> {
    let pair_summary = summarize_pairs(extraction);
    let mut image_paths = HashMap::new();
    let mut image_files = 0usize;
    if let Some(directory) = images_dir {
        prepare_output_directory(directory)?;
        let mut records = Vec::new();
        for (index, artifact) in extraction.artifacts.iter().enumerate() {
            let Some(bytes) = artifact.bytes.as_deref() else {
                continue;
            };
            let hash = format!("{:x}", Sha256::digest(bytes));
            let extension = image_extension(artifact.mime_type.as_deref());
            let filename = format!(
                "{index:03}-{}-{}-{}.{}",
                artifact.adapter.as_str(),
                safe_component(&artifact.challenge_kind),
                artifact.role.as_str(),
                extension,
            );
            write_new_file(&directory.join(&filename), bytes)?;
            image_paths.insert(index, filename.clone());
            image_files += 1;
            records.push(serde_json::json!({
                "adapter": artifact.adapter.as_str(),
                "captcha_type": artifact.challenge_kind,
                "challenge_id": artifact.challenge_id,
                "role": artifact.role.as_str(),
                "evidence": artifact.evidence_kind.as_str(),
                "frame_id": artifact.frame_id,
                "mime_type": artifact.mime_type,
                "bytes": bytes.len(),
                "sha256": hash,
                "path": filename,
            }));
        }
        let manifest = serde_json::json!({
            "version": 1,
            "scope": "slide-captcha-only",
            "complete": extraction.evidence_complete && pair_summary.groups != 0 && pair_summary.image_pairs == pair_summary.groups,
            "evidence_complete": extraction.evidence_complete,
            "diagnostic_count": extraction.diagnostics.len(),
            "challenge_groups": pair_summary.groups,
            "complete_source_pairs": pair_summary.source_pairs,
            "complete_image_pairs": pair_summary.image_pairs,
            "images": records,
        });
        write_new_file(
            &directory.join("manifest.json"),
            &serde_json::to_vec_pretty(&manifest)?,
        )?;
    }

    if let Some(path) = urls_output {
        let images = extraction
            .artifacts
            .iter()
            .enumerate()
            .map(|(index, artifact)| url_record(artifact, image_paths.get(&index)))
            .collect::<Vec<_>>();
        let report = serde_json::json!({
            "version": 1,
            "scope": "slide-captcha-only",
            "page_url": extraction.page_url,
            "diagnostics": extraction.diagnostics,
            "evidence_complete": extraction.evidence_complete,
            "challenge_groups": pair_summary.groups,
            "complete_source_pairs": pair_summary.source_pairs,
            "complete_image_pairs": pair_summary.image_pairs,
            "images": images,
        });
        let bytes = serde_json::to_vec_pretty(&report)?;
        if path == Path::new("-") {
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(&bytes)?;
            stdout.write_all(b"\n")?;
        } else {
            write_new_file(path, &bytes)?;
        }
    }

    Ok(CaptchaOutputSummary {
        discovered: extraction.artifacts.len(),
        groups: pair_summary.groups,
        image_files,
        unresolved_images: extraction
            .artifacts
            .iter()
            .filter(|artifact| artifact.bytes.is_none())
            .count(),
        source_pairs: pair_summary.source_pairs,
        image_pairs: pair_summary.image_pairs,
        evidence_complete: extraction.evidence_complete,
    })
}

#[derive(Default)]
struct PairState {
    background: bool,
    puzzle: bool,
    background_bytes: bool,
    puzzle_bytes: bool,
}

#[derive(Default)]
struct PairSummary {
    groups: usize,
    source_pairs: usize,
    image_pairs: usize,
}

fn summarize_pairs(extraction: &CaptchaExtraction) -> PairSummary {
    let mut groups: HashMap<(CaptchaAdapter, u32, String, String), PairState> = HashMap::new();
    for artifact in &extraction.artifacts {
        let state = groups
            .entry((
                artifact.adapter,
                artifact.frame_id,
                artifact.challenge_kind.clone(),
                artifact.challenge_id.clone(),
            ))
            .or_default();
        let source_is_usable = match artifact.source_kind {
            CaptchaSourceKind::DataUri | CaptchaSourceKind::InlineBase64 => {
                artifact.bytes.is_some()
            }
            CaptchaSourceKind::HttpUrl
            | CaptchaSourceKind::BlobUrl
            | CaptchaSourceKind::RelativeUrl => !artifact.source.is_empty(),
            CaptchaSourceKind::Other => false,
        };
        match artifact.role {
            CaptchaImageRole::Background => {
                state.background |= source_is_usable;
                state.background_bytes |= artifact.bytes.is_some();
            }
            CaptchaImageRole::Puzzle => {
                state.puzzle |= source_is_usable;
                state.puzzle_bytes |= artifact.bytes.is_some();
            }
        }
    }
    PairSummary {
        groups: extraction.challenge_groups.max(groups.len()),
        source_pairs: groups
            .values()
            .filter(|state| state.background && state.puzzle)
            .count(),
        image_pairs: groups
            .values()
            .filter(|state| state.background_bytes && state.puzzle_bytes)
            .count(),
    }
}

fn url_record(artifact: &CaptchaArtifact, image_path: Option<&String>) -> serde_json::Value {
    serde_json::json!({
        "adapter": artifact.adapter.as_str(),
        "captcha_type": artifact.challenge_kind,
        "challenge_id": artifact.challenge_id,
        "role": artifact.role.as_str(),
        "source_kind": artifact.source_kind.as_str(),
        "evidence": artifact.evidence_kind.as_str(),
        "source_value": artifact.source,
        "resolved_url": artifact.resolved_url,
        "page_frame": {
            "frame_id": artifact.frame_id,
            "frame_url": artifact.frame_url,
        },
        "response_url": artifact.response_url,
        "mime_type": artifact.mime_type,
        "bytes": artifact.bytes.as_ref().map(Vec::len),
        "sha256": artifact.bytes.as_ref().map(|bytes| format!("{:x}", Sha256::digest(bytes))),
        "image_path": image_path,
        "selector": artifact.selector,
    })
}

fn prepare_output_directory(directory: &Path) -> anyhow::Result<()> {
    match std::fs::symlink_metadata(directory) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                anyhow::bail!(
                    "CAPTCHA image output path must not be a symbolic link: {}",
                    directory.display()
                );
            }
            if !metadata.is_dir() {
                anyhow::bail!(
                    "CAPTCHA image output path is not a directory: {}",
                    directory.display()
                );
            }
            if std::fs::read_dir(directory)?.next().transpose()?.is_some() {
                anyhow::bail!(
                    "CAPTCHA image output directory must be empty: {}",
                    directory.display()
                );
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = directory
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
            {
                std::fs::create_dir_all(parent)?;
            }
            create_private_directory(directory)?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent().filter(|path| !path.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            anyhow::bail!(
                "CAPTCHA output target must not be a symbolic link: {}",
                path.display()
            );
        }
        anyhow::bail!("CAPTCHA output target already exists: {}", path.display());
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| anyhow::anyhow!("failed to create {}: {}", path.display(), error))?;
    file.write_all(bytes)
        .map_err(|error| anyhow::anyhow!("failed to write {}: {}", path.display(), error))
}

fn create_private_directory(path: &Path) -> anyhow::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(path).map_err(Into::into)
}

fn image_extension(mime_type: Option<&str>) -> &'static str {
    match mime_type.unwrap_or("").to_ascii_lowercase().as_str() {
        "image/png" => "png",
        "image/jpeg" | "image/jpg" => "jpg",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "image/bmp" => "bmp",
        "image/x-icon" | "image/vnd.microsoft.icon" => "ico",
        _ => "bin",
    }
}

fn safe_component(value: &str) -> String {
    let mut output = String::with_capacity(value.len().min(48));
    for character in value.chars().take(48) {
        if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
            output.push(character.to_ascii_lowercase());
        } else if !output.ends_with('-') {
            output.push('-');
        }
    }
    let output = output.trim_matches('-');
    if output.is_empty() {
        "slide".to_string()
    } else {
        output.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use obscura_browser::{
        CaptchaAdapter, CaptchaEvidenceKind, CaptchaImageRole, CaptchaSourceKind,
    };

    fn artifact(bytes: Option<Vec<u8>>) -> CaptchaArtifact {
        CaptchaArtifact {
            adapter: CaptchaAdapter::AjCaptcha,
            challenge_kind: "block_puzzle".to_string(),
            challenge_id: "aj-captcha-0".to_string(),
            role: CaptchaImageRole::Background,
            source_kind: CaptchaSourceKind::InlineBase64,
            evidence_kind: CaptchaEvidenceKind::ApiResponse,
            source: "data:image/png;base64,AA==".to_string(),
            resolved_url: None,
            frame_id: 0,
            frame_url: "https://example.test/login".to_string(),
            response_url: Some("https://example.test/captcha/get".to_string()),
            selector: None,
            mime_type: Some("image/png".to_string()),
            bytes,
        }
    }

    #[test]
    fn safe_component_never_creates_path_components() {
        assert_eq!(safe_component("../Block Puzzle/测试"), "block-puzzle");
        assert_eq!(safe_component(""), "slide");
    }

    #[test]
    fn image_manifest_does_not_copy_sources_or_response_urls() {
        let root =
            std::env::temp_dir().join(format!("obscura-captcha-output-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let extraction = CaptchaExtraction {
            page_url: "https://example.test/login?secret=page".to_string(),
            artifacts: vec![artifact(Some(b"png".to_vec()))],
            diagnostics: vec![
                "failed https://user:pass@example.test/captcha?token=secret".to_string()
            ],
            challenge_groups: 1,
            evidence_complete: false,
        };
        write_captcha_outputs(&extraction, Some(&root), None).unwrap();
        let manifest = std::fs::read_to_string(root.join("manifest.json")).unwrap();
        assert!(!manifest.contains("base64"));
        assert!(!manifest.contains("captcha/get"));
        assert!(!manifest.contains("secret=page"));
        assert!(!manifest.contains("token=secret"));
        assert!(!manifest.contains("user:pass"));
        let manifest: serde_json::Value = serde_json::from_str(&manifest).unwrap();
        assert_eq!(manifest["complete"], false);
        assert_eq!(manifest["evidence_complete"], false);
        assert_eq!(manifest["diagnostic_count"], 1);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn completeness_requires_both_roles_and_both_payloads() {
        let background = artifact(Some(vec![1]));
        let mut puzzle = artifact(Some(vec![2]));
        puzzle.role = CaptchaImageRole::Puzzle;
        let complete = CaptchaExtraction {
            page_url: "https://example.test/".to_string(),
            artifacts: vec![background.clone(), puzzle.clone()],
            diagnostics: Vec::new(),
            challenge_groups: 1,
            evidence_complete: true,
        };
        let summary = summarize_pairs(&complete);
        assert_eq!(summary.source_pairs, 1);
        assert_eq!(summary.image_pairs, 1);

        puzzle.bytes = None;
        let partial = CaptchaExtraction {
            page_url: "https://example.test/".to_string(),
            artifacts: vec![background, puzzle],
            diagnostics: Vec::new(),
            challenge_groups: 1,
            evidence_complete: true,
        };
        let summary = summarize_pairs(&partial);
        assert_eq!(summary.source_pairs, 0);
        assert_eq!(summary.image_pairs, 0);

        let mut remote_puzzle = artifact(None);
        remote_puzzle.role = CaptchaImageRole::Puzzle;
        remote_puzzle.source_kind = CaptchaSourceKind::HttpUrl;
        remote_puzzle.source = "https://example.test/puzzle.png".to_string();
        let remote_pair = CaptchaExtraction {
            page_url: "https://example.test/".to_string(),
            artifacts: vec![artifact(Some(vec![1])), remote_puzzle],
            diagnostics: Vec::new(),
            challenge_groups: 1,
            evidence_complete: true,
        };
        let summary = summarize_pairs(&remote_pair);
        assert_eq!(summary.source_pairs, 1);
        assert_eq!(summary.image_pairs, 0);

        let mut untrusted_other = artifact(None);
        untrusted_other.role = CaptchaImageRole::Puzzle;
        untrusted_other.source_kind = CaptchaSourceKind::Other;
        untrusted_other.source = "javascript:unexpected".to_string();
        let other_pair = CaptchaExtraction {
            page_url: "https://example.test/".to_string(),
            artifacts: vec![artifact(Some(vec![1])), untrusted_other],
            diagnostics: Vec::new(),
            challenge_groups: 1,
            evidence_complete: true,
        };
        let summary = summarize_pairs(&other_pair);
        assert_eq!(summary.source_pairs, 0);
        assert_eq!(summary.image_pairs, 0);

        let instance_a = artifact(Some(vec![1]));
        let mut instance_b = artifact(Some(vec![2]));
        instance_b.challenge_id = "aj-captcha-1".to_string();
        instance_b.role = CaptchaImageRole::Puzzle;
        let cross_instance = CaptchaExtraction {
            page_url: "https://example.test/".to_string(),
            artifacts: vec![instance_a, instance_b],
            diagnostics: Vec::new(),
            challenge_groups: 2,
            evidence_complete: true,
        };
        let summary = summarize_pairs(&cross_instance);
        assert_eq!(summary.groups, 2);
        assert_eq!(summary.source_pairs, 0);
        assert_eq!(summary.image_pairs, 0);

        let background = artifact(Some(vec![1]));
        let mut puzzle = artifact(Some(vec![2]));
        puzzle.role = CaptchaImageRole::Puzzle;
        let missing_mounted_instance = CaptchaExtraction {
            page_url: "https://example.test/".to_string(),
            artifacts: vec![background, puzzle],
            diagnostics: Vec::new(),
            challenge_groups: 2,
            evidence_complete: true,
        };
        let summary = summarize_pairs(&missing_mounted_instance);
        assert_eq!(summary.groups, 2);
        assert_eq!(summary.source_pairs, 1);
        assert_eq!(summary.image_pairs, 1);
    }
}
