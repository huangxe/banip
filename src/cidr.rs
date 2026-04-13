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
/// Only converts if the range is a clean power-of-2 block aligned to its size.
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

    let start_addr = std::net::Ipv4Addr::from_str(parts[0].trim()).ok()?;
    let end_addr = std::net::Ipv4Addr::from_str(parts[1].trim()).ok()?;

    let start: u32 = start_addr.into();
    let end: u32 = end_addr.into();

    if start > end {
        return None;
    }

    // Convert IP range to a single CIDR if it's a clean power-of-2 block
    let range = end - start + 1;
    if range.is_power_of_two() && (start & (range - 1)) == 0 {
        let prefix_len = 32 - range.trailing_zeros();
        let net = Ipv4Net::new(start_addr, prefix_len as u8).ok()?;
        Some(net)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cidr_list_basic() {
        let input = "1.0.1.0/24\n1.0.2.0/23\n";
        let result = parse_cidr_list(input);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].to_string(), "1.0.1.0/24");
        assert_eq!(result[1].to_string(), "1.0.2.0/23");
    }

    #[test]
    fn test_parse_cidr_list_skips_comments() {
        let input = "# this is a comment\n1.0.1.0/24\n# another comment\n1.0.2.0/23\n";
        let result = parse_cidr_list(input);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_parse_cidr_list_skips_empty_lines() {
        let input = "\n\n1.0.1.0/24\n\n\n1.0.2.0/23\n\n";
        let result = parse_cidr_list(input);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_parse_cidr_list_deduplication() {
        let input = "1.0.1.0/24\n1.0.2.0/23\n1.0.1.0/24\n1.0.2.0/23\n";
        let result = parse_cidr_list(input);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_parse_cidr_list_sorted() {
        let input = "1.0.2.0/23\n1.0.1.0/24\n10.0.0.0/8\n";
        let result = parse_cidr_list(input);
        assert_eq!(result[0].to_string(), "1.0.1.0/24");
        assert_eq!(result[1].to_string(), "1.0.2.0/23");
        assert_eq!(result[2].to_string(), "10.0.0.0/8");
    }

    #[test]
    fn test_parse_cidr_list_skips_malformed() {
        let input = "1.0.1.0/24\nnot-a-cidr\n999.999.999.999/24\n1.0.2.0/23\n";
        let result = parse_cidr_list(input);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_parse_cidr_list_empty_input() {
        let result = parse_cidr_list("");
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_cidr_list_only_comments() {
        let result = parse_cidr_list("# comment1\n# comment2\n");
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_ip_range_dash() {
        let result = parse_ip_range("1.0.1.0 - 1.0.1.255");
        assert!(result.is_some());
        assert_eq!(result.unwrap().to_string(), "1.0.1.0/24");
    }

    #[test]
    fn test_parse_ip_range_comma() {
        let result = parse_ip_range("1.0.1.0,1.0.1.255");
        assert!(result.is_some());
        assert_eq!(result.unwrap().to_string(), "1.0.1.0/24");
    }

    #[test]
    fn test_parse_ip_range_invalid_range() {
        // start > end
        let result = parse_ip_range("1.0.1.255 - 1.0.1.0");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_ip_range_not_power_of_two() {
        // 1.0.1.0 to 1.0.1.100 = 101 addresses, not a power of 2
        let result = parse_ip_range("1.0.1.0 - 1.0.1.100");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_ip_range_not_aligned() {
        // 1.0.1.1 to 1.0.1.255 = 255 addresses, power of 2 but not aligned
        let result = parse_ip_range("1.0.1.1 - 1.0.1.255");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_ip_range_single_ip() {
        // Single IP = /32
        let result = parse_ip_range("1.0.1.0 - 1.0.1.0");
        assert!(result.is_some());
        assert_eq!(result.unwrap().to_string(), "1.0.1.0/32");
    }

    #[test]
    fn test_parse_ip_range_large_block() {
        // /16 block
        let result = parse_ip_range("10.0.0.0 - 10.0.255.255");
        assert!(result.is_some());
        assert_eq!(result.unwrap().to_string(), "10.0.0.0/16");
    }

    #[test]
    fn test_parse_cidr_list_mixed_formats() {
        // CIDR + dash range + comment
        let input = "1.0.1.0/24\n1.0.2.0 - 1.0.3.255\n# comment\n";
        let result = parse_cidr_list(input);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].to_string(), "1.0.1.0/24");
        assert_eq!(result[1].to_string(), "1.0.2.0/23");
    }

    #[test]
    fn test_parse_ip_range_no_separator() {
        let result = parse_ip_range("1.0.1.0 1.0.1.255");
        assert!(result.is_none());
    }
}
