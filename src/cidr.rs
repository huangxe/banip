use ipnet::Ipv4Net;
use std::str::FromStr;

/// Parse a list of CIDR ranges from raw text content.
/// Skips empty lines, comments (lines starting with #), and malformed entries.
/// Returns deduplicated and sorted CIDR ranges.
pub fn parse_cidr_list(content: &str) -> Vec<Ipv4Net> {
    let mut cidrs: Vec<Ipv4Net> = content
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            // Some files may have format: "start_ip - end_ip" or "start_ip,end_ip"
            // Try CIDR first, then range formats
            if let Ok(net) = Ipv4Net::from_str(line) {
                Some(net)
            } else if let Some(net) = parse_ip_range(line) {
                Some(net)
            } else {
                None
            }
        })
        .collect();

    // Deduplicate and sort
    cidrs.sort_by(|a, b| a.network().cmp(&b.network()));
    cidrs.dedup_by(|a, b| a.network() == b.network());

    cidrs
}

/// Parse IP range in "start - end" or "start,end" format and convert to CIDR.
fn parse_ip_range(line: &str) -> Option<Ipv4Net> {
    let parts: Vec<&str> = if line.contains('-') {
        line.split('-').collect()
    } else if line.contains(',') {
        line.split(',').collect()
    } else {
        return None;
    };

    if parts.len() != 2 {
        return None;
    }

    let start: u32 = parts[0].trim().parse().ok()?;
    let end: u32 = parts[1].trim().parse().ok()?;

    if start > end {
        return None;
    }

    // Convert IP range to a single CIDR if it's a clean power-of-2 block
    let range = end - start + 1;
    if range.is_power_of_two() && (start & (range - 1)) == 0 {
        let prefix_len = 32 - range.trailing_zeros();
        let net = Ipv4Net::new(
            std::net::Ipv4Addr::from(start),
            prefix_len as u8,
        )
        .ok()?;
        Some(net)
    } else {
        // Not a clean CIDR block — split into multiple CIDRs
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cidr_list() {
        let input = "# comment\n1.0.1.0/24\n1.0.2.0/23\n\n1.0.1.0/24\n";
        let result = parse_cidr_list(input);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].to_string(), "1.0.1.0/24");
        assert_eq!(result[1].to_string(), "1.0.2.0/23");
    }

    #[test]
    fn test_parse_ip_range() {
        let result = parse_ip_range("1.0.1.0 - 1.0.1.255");
        assert!(result.is_some());
        assert_eq!(result.unwrap().to_string(), "1.0.1.0/24");
    }
}
