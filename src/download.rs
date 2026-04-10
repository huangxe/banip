use std::io::Write;

/// Default URL for downloading China IP CIDR list.
pub const DEFAULT_CN_IP_URL: &str =
    "https://raw.githubusercontent.com/isxpy/China-ip-range/main/cnip_cidr.txt";

/// Alternative URLs in case the primary one fails.
const FALLBACK_URLS: &[&str] = &[
    "https://raw.githubusercontent.com/isxpy/China-ip-range/main/cnip_cidr.txt",
    "https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt",
];

/// Download China IP CIDR list from the given URL.
/// Tries fallback URLs on failure.
pub fn download_cn_ip_list(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let urls: Vec<&str> = if FALLBACK_URLS.contains(&url) {
        FALLBACK_URLS.to_vec()
    } else {
        let mut urls = vec![url];
        urls.extend_from_slice(FALLBACK_URLS);
        urls
    };

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()?;

    let mut last_err = String::new();

    for (i, try_url) in urls.iter().enumerate() {
        if i > 0 {
            println!("   Retrying with fallback URL...");
        }
        print!("   ⬇️  Downloading... ");
        std::io::stderr().flush().ok();

        match client.get(*try_url).send() {
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
