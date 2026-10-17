//! Exact decimal ⇄ integer conversion (no floating point anywhere).

use ethnum::U256;

use crate::TxError;

/// "1.5" with 18 decimals → 1_500_000_000_000_000_000.
pub fn parse_units(input: &str, decimals: u8) -> Result<U256, TxError> {
    let s = input.trim().replace('_', "");
    if s.is_empty() {
        return Err(TxError::Input("enter an amount".into()));
    }
    if s.contains(',') {
        return Err(TxError::Input("use a dot for decimals and no thousands separators".into()));
    }
    let (int, frac) = match s.split_once('.') {
        Some((i, f)) => (i, f),
        None => (s.as_str(), ""),
    };
    if int.is_empty() && frac.is_empty() || !int.chars().chain(frac.chars()).all(|c| c.is_ascii_digit()) {
        return Err(TxError::Input(format!("'{}' is not a valid amount", input.trim())));
    }
    let frac = frac.trim_end_matches('0');
    if frac.len() > decimals as usize {
        return Err(TxError::Input(format!("too many decimal places (this asset has {decimals})")));
    }
    let digits = format!("{}{:0<width$}", if int.is_empty() { "0" } else { int }, frac, width = decimals as usize);
    let value = U256::from_str_radix(&digits, 10).map_err(|_| TxError::Input("amount is too large".into()))?;
    if value == U256::ZERO {
        return Err(TxError::Input("amount must be greater than zero".into()));
    }
    Ok(value)
}

/// 1_500_000_000_000_000_000 with 18 decimals → "1.5".
pub fn format_units(value: U256, decimals: u8) -> String {
    let digits = value.to_string();
    let d = decimals as usize;
    if d == 0 {
        return digits;
    }
    let padded = format!("{digits:0>width$}", width = d + 1);
    let (int, frac) = padded.split_at(padded.len() - d);
    let frac = frac.trim_end_matches('0');
    if frac.is_empty() {
        int.to_string()
    } else {
        format!("{int}.{frac}")
    }
}

/// Shorter display: at most `max_frac` decimals, rounded down, with "…" marker
/// if truncated. Used for balances in the UI.
pub fn format_short(value: U256, decimals: u8, max_frac: usize) -> String {
    let full = format_units(value, decimals);
    match full.split_once('.') {
        Some((i, f)) if f.len() > max_frac => {
            let f = f[..max_frac].trim_end_matches('0');
            if f.is_empty() {
                format!("{i}…")
            } else {
                format!("{i}.{f}…")
            }
        }
        _ => full,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        assert_eq!(parse_units("1.5", 18).unwrap(), U256::from(1_500_000_000_000_000_000u128));
        assert_eq!(parse_units(".25", 2).unwrap(), U256::from(25u32));
        assert_eq!(parse_units("10", 6).unwrap(), U256::from(10_000_000u32));
        assert_eq!(parse_units("1.000", 0).unwrap(), U256::from(1u32));
        assert_eq!(parse_units("1_000.1", 1).unwrap(), U256::from(10_001u32));
        assert!(parse_units("1.0000001", 6).is_err());
        assert!(parse_units("0", 6).is_err());
        assert!(parse_units("abc", 6).is_err());
        assert!(parse_units("1,5", 6).is_err());
        assert!(parse_units("-1", 6).is_err());
        assert!(parse_units(".", 6).is_err());
        assert!(parse_units("1e9", 6).is_err());
        // Huge meme-coin supply × 18 decimals still fits.
        assert!(parse_units("1000000000000000000", 18).is_ok());
    }

    #[test]
    fn format() {
        assert_eq!(format_units(U256::from(1_500_000_000_000_000_000u128), 18), "1.5");
        assert_eq!(format_units(U256::from(1u32), 18), "0.000000000000000001");
        assert_eq!(format_units(U256::ZERO, 9), "0");
        assert_eq!(format_units(U256::from(123u32), 0), "123");
        assert_eq!(format_short(U256::from(1_234_567_891u64), 9, 4), "1.2345…");
        assert_eq!(format_short(U256::from(1_000_000_000u64), 9, 4), "1");
    }

    #[test]
    fn roundtrip() {
        for (s, d) in [("0.1", 18), ("123.456", 6), ("42", 0), ("0.000000001", 9)] {
            assert_eq!(format_units(parse_units(s, d).unwrap(), d), s);
        }
    }
}
