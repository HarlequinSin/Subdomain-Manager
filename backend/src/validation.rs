use regex::Regex;

pub fn normalize_label(label: &str) -> String {
    label.trim().to_lowercase().replace('_', "-")
}

pub fn validate_label(label: &str) -> Result<(), anyhow::Error> {
    static LABEL_REGEX: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$").expect("label regex must compile")
    });

    if LABEL_REGEX.is_match(label) {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "invalid subdomain label: only lowercase letters, numbers and dashes are allowed"
        ))
    }
}

pub fn normalize_record_type(record_type: &str) -> String {
    record_type.trim().to_uppercase()
}

pub fn validate_record_type(record_type: &str) -> Result<(), anyhow::Error> {
    const ALLOWED: &[&str] = &["A", "AAAA", "CNAME", "SRV", "TXT"];

    if ALLOWED.contains(&record_type) {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "unsupported record type. allowed values are A, AAAA, CNAME, SRV, TXT"
        ))
    }
}

pub fn validate_regex(pattern: &str) -> Result<(), anyhow::Error> {
    Regex::new(pattern)
        .map(|_| ())
        .map_err(|err| anyhow::anyhow!("invalid regex pattern: {err}"))
}

pub fn validate_domain(base_domain: &str) -> Result<(), anyhow::Error> {
    let cleaned = base_domain.trim().trim_matches('.').to_lowercase();

    if cleaned.is_empty() || cleaned.len() > 255 {
        return Err(anyhow::anyhow!("invalid managed domain"));
    }

    if cleaned
        .split('.')
        .any(|segment| segment.is_empty() || segment.len() > 63)
    {
        return Err(anyhow::anyhow!(
            "invalid managed domain: each label must be 1-63 characters"
        ));
    }

    Ok(())
}
