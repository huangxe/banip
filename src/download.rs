use std::io::Write;

/// Default URL for downloading China IP CIDR list.
pub const DEFAULT_CN_IP_URL: &str =
    "https://raw.githubusercontent.com/isxpy/China-ip-range/main/cnip_cidr.txt";

/// Alternative URLs in case the primary one fails.
const FALLBACK_URLS: &[&str] = &[
    "https://raw.githubusercontent.com/isxpy/China-ip-range/main/cnip_cidr.txt",
    "https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt",
];

/// Build the ordered list of URLs to try for downloading.
pub fn build_url_list(url: &str) -> Vec<String> {
    if FALLBACK_URLS.contains(&url) {
        FALLBACK_URLS.iter().map(|s| s.to_string()).collect()
    } else {
        // Custom URL first, then fallbacks (excluding duplicates)
        let mut urls = vec![url.to_string()];
        for fb in FALLBACK_URLS {
            if *fb != url {
                urls.push(fb.to_string());
            }
        }
        urls
    }
}

/// Validate that downloaded content looks like a valid CIDR list.
/// Returns the number of valid CIDR lines found.
pub fn validate_cidr_content(content: &str) -> usize {
    content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter(|l| {
            // Simple validation: contains '/' and looks like a.b.c.d/N
            l.contains('/') && l.split('/').count() == 2
        })
        .count()
}

/// Download China IP CIDR list from the given URL.
/// Tries fallback URLs on failure.
pub fn download_cn_ip_list(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let urls = build_url_list(url);

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()?;

    let mut last_err = String::new();

    for (i, try_url) in urls.iter().enumerate() {
        if i > 0 {
            println!("   Retrying with fallback URL...");
        }
        print!("   Downloading... ");
        std::io::stderr().flush().ok();

        match client.get(try_url.as_str()).send() {
            Ok(resp) => {
                if resp.status().is_success() {
                    let bytes = resp.bytes()?;
                    let text = String::from_utf8_lossy(&bytes).into_owned();
                    println!("OK ({} bytes)", bytes.len());
                    return Ok(text);
                } else {
                    last_err = format!("HTTP {}", resp.status());
                    println!("FAILED ({})", last_err);
                }
            }
            Err(e) => {
                last_err = e.to_string();
                println!("FAILED ({})", last_err);
            }
        }
    }

    Err(format!(
        "All download attempts failed. Last error: {}",
        last_err
    )
    .into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_url_is_first_fallback() {
        assert_eq!(DEFAULT_CN_IP_URL, FALLBACK_URLS[0]);
    }

    #[test]
    fn test_build_url_list_default() {
        let urls = build_url_list(DEFAULT_CN_IP_URL);
        // When default URL matches a fallback, should return all fallbacks
        assert!(urls.len() >= 2);
        assert_eq!(urls[0], DEFAULT_CN_IP_URL);
    }

    #[test]
    fn test_build_url_list_custom() {
        let custom = "https://example.com/custom.txt";
        let urls = build_url_list(custom);
        assert_eq!(urls[0], custom);
        // Should contain fallbacks after custom URL
        assert!(urls.len() > 1);
    }

    #[test]
    fn test_build_url_list_custom_same_as_fallback() {
        // If custom URL equals a fallback, no duplicate
        let urls = build_url_list(FALLBACK_URLS[1]);
        let count = urls.iter().filter(|u| *u == FALLBACK_URLS[1]).count();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_fallback_urls_count() {
        assert_eq!(FALLBACK_URLS.len(), 2);
    }

    #[test]
    fn test_validate_cidr_content_valid() {
        let content = "1.0.1.0/24\n1.0.2.0/23\n10.0.0.0/8\n";
        assert_eq!(validate_cidr_content(content), 3);
    }

    #[test]
    fn test_validate_cidr_content_with_comments() {
        let content = "# China IPs\n1.0.1.0/24\n# another\n1.0.2.0/23\n";
        assert_eq!(validate_cidr_content(content), 2);
    }

    #[test]
    fn test_validate_cidr_content_with_empty_lines() {
        let content = "\n1.0.1.0/24\n\n\n1.0.2.0/23\n";
        assert_eq!(validate_cidr_content(content), 2);
    }

    #[test]
    fn test_validate_cidr_content_empty() {
        assert_eq!(validate_cidr_content(""), 0);
    }

    #[test]
    fn test_validate_cidr_content_invalid() {
        let content = "not-a-cidr\nstill-not\n1.0.1.0/24\n";
        assert_eq!(validate_cidr_content(content), 1);
    }

    #[test]
    fn test_validate_cidr_content_malformed_prefix() {
        let content = "1.0.1.0/24\n1.0.1.0/33\n"; // /33 is invalid but passes simple check
        assert_eq!(validate_cidr_content(content), 2);
    }

    #[test]
    fn test_validate_cidr_content_only_comments() {
        let content = "# comment1\n# comment2\n";
        assert_eq!(validate_cidr_content(content), 0);
    }

    #[test]
    fn test_validate_cidr_content_large_list() {
        let mut content = String::new();
        for i in 0..1000 {
            content.push_str(&format!("{}.{}.0.0/16\n", i / 256, i % 256));
        }
        assert_eq!(validate_cidr_content(&content), 1000);
    }
}
