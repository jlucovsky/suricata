/* Copyright (C) 2026 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

//! FTP protocol parsers using nom.

use crate::ftp::constant::FtpRequestCommand;
use nom8::bytes::complete::{tag, take_until, take_while1};
use nom8::character::complete::{digit1, multispace0};
use nom8::combinator::{complete, map_res, opt, verify};
use nom8::sequence::delimited;
use nom8::{Err, IResult, Parser};
use std::str;
use std::str::FromStr;

/// A parsed FTP request line (zero-copy view into the input).
pub struct FtpRequestLine<'a> {
    pub command: FtpRequestCommand,
    /// Raw bytes of the command name (e.g. b"USER")
    pub command_name: &'a [u8],
    /// Argument bytes, i.e. everything after the separating space (may be empty/None).
    pub arg: Option<&'a [u8]>,
}

/// A parsed FTP response line (owned data).
#[derive(Debug, Clone)]
pub struct FtpResponseLine {
    /// The 3-digit numeric code.
    pub code: u16,
    /// true when the separator between code and text is '-' (multi-line continuation).
    pub is_continuation: bool,
    /// The text after the code and separator, without trailing \r\n.
    pub message: Vec<u8>,
    /// Raw 3-character code bytes (for logging without re-formatting).
    pub code_str: [u8; 3],
}

// ─── Internal helper parsers ─────────────────────────────────────────────────

/// Parse an ASCII alphabetic command token (up to the end-of-line or first
/// space/tab).
fn ftp_command_token(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while1(|c: u8| c.is_ascii_alphabetic())(input)
}

// ─── Public parsers ───────────────────────────────────────────────────────────

/// Parse a single FTP request line that has already been stripped of its
/// trailing `\r\n` (or just `\n`).
///
/// The `input` slice must be the content of a single line *without* the line
/// terminator.
pub fn parse_request_line(input: &[u8]) -> IResult<&[u8], FtpRequestLine<'_>> {
    let (rem, name) = ftp_command_token(input)?;

    // Optional: one or more spaces followed by the argument.
    let arg = if !rem.is_empty() && (rem[0] == b' ' || rem[0] == b'\t') {
        let arg_bytes = &rem[1..]; // skip the single separator
        if arg_bytes.is_empty() {
            None
        } else {
            Some(arg_bytes)
        }
    } else {
        None
    };

    // AUTH TLS is a two-token command on the wire ("AUTH TLS").  Detect it by
    // checking the name and argument rather than expecting "AUTH_TLS" as a
    // single token.
    let command = if name.eq_ignore_ascii_case(b"AUTH")
        && matches!(arg, Some(a) if a.eq_ignore_ascii_case(b"TLS"))
    {
        FtpRequestCommand::FTP_COMMAND_AUTH_TLS
    } else {
        FtpRequestCommand::from_name(name)
    };

    Ok((
        b"",
        FtpRequestLine {
            command,
            command_name: name,
            arg,
        },
    ))
}

/// Parse a single FTP response line that has already been stripped of its
/// trailing `\r\n` (or `\n`).
///
/// The `input` slice must be the content of a single line *without* the line
/// terminator.
pub fn parse_response_line(input: &[u8]) -> IResult<&[u8], FtpResponseLine> {
    // Minimum viable response: 3 digits + separator.
    if input.len() < 3 {
        return Err(Err::Error(nom8::error::Error::new(
            input,
            nom8::error::ErrorKind::Digit,
        )));
    }

    // Validate 3-digit code.
    if !input[0].is_ascii_digit() || !input[1].is_ascii_digit() || !input[2].is_ascii_digit() {
        return Err(Err::Error(nom8::error::Error::new(
            input,
            nom8::error::ErrorKind::Digit,
        )));
    }

    let code_str = [input[0], input[1], input[2]];
    let code_val = (code_str[0] - b'0') as u16 * 100
        + (code_str[1] - b'0') as u16 * 10
        + (code_str[2] - b'0') as u16;

    // The 4th byte is either ' ' (final reply) or '-' (continuation).
    let (is_continuation, msg_start) = if input.len() >= 4 {
        match input[3] {
            b'-' => (true, &input[4..]),
            b' ' => (false, &input[4..]),
            _ => (false, &input[3..]),
        }
    } else {
        (false, &input[3..])
    };

    Ok((
        b"",
        FtpResponseLine {
            code: code_val,
            is_continuation,
            message: msg_start.to_vec(),
            code_str,
        },
    ))
}

/// Returns true for 1xx preliminary responses.
#[inline]
pub fn is_preliminary_response(code: u16) -> bool {
    code >= 100 && code < 200
}

// ─── Port parsers (migrated from mod.rs) ──────────────────────────────────────

fn parse_u16(i: &[u8]) -> IResult<&[u8], u16> {
    map_res(map_res(digit1, str::from_utf8), u16::from_str).parse(i)
}

fn getu16(i: &[u8]) -> IResult<&[u8], u16> {
    delimited(multispace0, parse_u16, multispace0).parse(i)
}

/// PORT 192,168,0,13,234,10  →  port number
pub fn ftp_active_port(i: &[u8]) -> IResult<&[u8], u16> {
    let (i, _) = tag("PORT").parse(i)?;
    let (i, _) = delimited(multispace0, digit1, multispace0).parse(i)?;
    let (i, _) = (
        tag(","),
        digit1,
        tag(","),
        digit1,
        tag(","),
        digit1,
        tag(","),
    )
        .parse(i)?;
    let (i, part1) = verify(parse_u16, |&v| v <= u8::MAX as u16).parse(i)?;
    let (i, _) = tag(",").parse(i)?;
    let (i, part2) = verify(parse_u16, |&v| v <= u8::MAX as u16).parse(i)?;
    Ok((i, part1 * 256 + part2))
}

/// 227 Entering Passive Mode (212,27,32,66,221,243).  →  port number
pub fn ftp_pasv_response(i: &[u8]) -> IResult<&[u8], u16> {
    let (i, _) = tag("227").parse(i)?;
    let (i, _) = take_until("(").parse(i)?;
    let (i, _) = tag("(").parse(i)?;
    let (i, _) = (
        digit1,
        tag(","),
        digit1,
        tag(","),
        digit1,
        tag(","),
        digit1,
        tag(","),
    )
        .parse(i)?;
    let (i, part1) = verify(getu16, |&v| v <= u8::MAX as u16).parse(i)?;
    let (i, _) = tag(",").parse(i)?;
    let (i, part2) = verify(getu16, |&v| v <= u8::MAX as u16).parse(i)?;
    let (i, _) = tag(")").parse(i)?;
    let (i, _) = opt(complete(tag("."))).parse(i)?;
    Ok((i, part1 * 256 + part2))
}

/// 229 Entering Extended Passive Mode (|||48758|).  →  port number
pub fn ftp_epsv_response(i: &[u8]) -> IResult<&[u8], u16> {
    let (i, _) = tag("229").parse(i)?;
    let (i, _) = take_until("|||").parse(i)?;
    let (i, _) = tag("|||").parse(i)?;
    let (i, port) = getu16(i)?;
    let (i, _) = tag("|)").parse(i)?;
    let (i, _) = opt(complete(tag("."))).parse(i)?;
    Ok((i, port))
}

/// EPRT |2|2a01:...|41813|  →  port number
pub fn ftp_active_eprt(i: &[u8]) -> IResult<&[u8], u16> {
    let (i, _) = tag("EPRT").parse(i)?;
    let (i, _) = take_until("|").parse(i)?;
    let (i, _) = tag("|").parse(i)?;
    let (i, _) = take_until("|").parse(i)?;
    let (i, _) = tag("|").parse(i)?;
    let (i, _) = take_until("|").parse(i)?;
    let (i, _) = tag("|").parse(i)?;
    let (i, port) = getu16(i)?;
    let (i, _) = tag("|").parse(i)?;
    Ok((i, port))
}

// ─── Convenience wrappers exposed to ftp.rs ──────────────────────────────────

/// Parse PORT/EPRT arg bytes for active-mode port.  Returns 0 on failure.
pub fn parse_port_from_line(input: &[u8]) -> u16 {
    match ftp_active_port(input) {
        Ok((_, p)) => p,
        _ => 0,
    }
}

/// Parse EPRT arg bytes for active-mode IPv6 port.  Returns 0 on failure.
pub fn parse_eprt_from_line(input: &[u8]) -> u16 {
    match ftp_active_eprt(input) {
        Ok((_, p)) => p,
        _ => 0,
    }
}

/// Parse PASV response line for passive-mode port.  Returns 0 on failure.
pub fn parse_pasv_port(input: &[u8]) -> u16 {
    match ftp_pasv_response(input) {
        Ok((_, p)) => p,
        _ => 0,
    }
}

/// Parse EPSV response line for passive-mode IPv6 port.  Returns 0 on failure.
pub fn parse_epsv_port(input: &[u8]) -> u16 {
    match ftp_epsv_response(input) {
        Ok((_, p)) => p,
        _ => 0,
    }
}

// ─── Line extraction helper ───────────────────────────────────────────────────

/// Extract a complete line from `buf` (up to and including `\n`), stripping the
/// `\r\n` or bare `\n` delimiter.
///
/// Returns `Some((line_without_delim, bytes_consumed))` or `None` if no
/// complete line is available.
///
/// If the line (without delimiter) exceeds `max_len`, truncation is indicated
/// by returning the first `max_len` bytes with `truncated = true`.
pub fn extract_line(buf: &[u8], max_len: usize) -> Option<(Vec<u8>, usize, bool)> {
    if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
        // Total bytes consumed including the \n.
        let consumed = pos + 1;
        // Line without delimiter.
        let end = if pos > 0 && buf[pos - 1] == b'\r' {
            pos - 1
        } else {
            pos
        };
        let line = &buf[..end];
        if line.len() >= max_len {
            // Truncate: >= because the buffer is capped at max_len before '\n' arrives,
            // so a line of exactly max_len bytes was originally longer.
            Some((line[..max_len].to_vec(), consumed, true))
        } else {
            Some((line.to_vec(), consumed, false))
        }
    } else {
        // No newline yet.
        None
    }
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_request_user() {
        let line = b"USER anonymous";
        let (_, req) = parse_request_line(line).unwrap();
        assert!(matches!(req.command, FtpRequestCommand::FTP_COMMAND_USER));
        assert_eq!(req.command_name, b"USER");
        assert_eq!(req.arg, Some(b"anonymous".as_ref()));
    }

    #[test]
    fn test_parse_request_pasv() {
        let line = b"PASV";
        let (_, req) = parse_request_line(line).unwrap();
        assert!(matches!(req.command, FtpRequestCommand::FTP_COMMAND_PASV));
        assert_eq!(req.arg, None);
    }

    #[test]
    fn test_parse_request_port() {
        let line = b"PORT 192,168,0,13,234,10";
        let (_, req) = parse_request_line(line).unwrap();
        assert!(matches!(req.command, FtpRequestCommand::FTP_COMMAND_PORT));
        assert_eq!(req.arg, Some(b"192,168,0,13,234,10".as_ref()));
    }

    #[test]
    fn test_parse_request_unknown() {
        let line = b"XYZZY somefile";
        let (_, req) = parse_request_line(line).unwrap();
        assert!(matches!(
            req.command,
            FtpRequestCommand::FTP_COMMAND_UNKNOWN
        ));
    }

    #[test]
    fn test_parse_response_single() {
        let line = b"220 Welcome to FTP server";
        let (_, resp) = parse_response_line(line).unwrap();
        assert_eq!(resp.code, 220);
        assert!(!resp.is_continuation);
        assert_eq!(resp.message, b"Welcome to FTP server");
    }

    #[test]
    fn test_parse_response_continuation() {
        let line = b"220-Multi-line banner";
        let (_, resp) = parse_response_line(line).unwrap();
        assert_eq!(resp.code, 220);
        assert!(resp.is_continuation);
        assert_eq!(resp.message, b"Multi-line banner");
    }

    #[test]
    fn test_parse_response_227() {
        let line = b"227 Entering Passive Mode (212,27,32,66,221,243)";
        let (_, resp) = parse_response_line(line).unwrap();
        assert_eq!(resp.code, 227);
        let port = parse_pasv_port(&[b"227 Entering Passive Mode (212,27,32,66,221,243)".as_ref(), b"."].concat());
        assert_eq!(port, 56819);
    }

    #[test]
    fn test_is_preliminary_response() {
        assert!(is_preliminary_response(150));
        assert!(!is_preliminary_response(200));
        assert!(!is_preliminary_response(230));
    }

    #[test]
    fn test_extract_line_crlf() {
        let buf = b"USER anon\r\nPASS x\r\n";
        let result = extract_line(buf, 4096);
        assert!(result.is_some());
        let (line, consumed, truncated) = result.unwrap();
        assert_eq!(line, b"USER anon");
        assert_eq!(consumed, 11); // "USER anon\r\n" = 11 bytes
        assert!(!truncated);
    }

    #[test]
    fn test_extract_line_lf_only() {
        let buf = b"USER anon\nPASS x\n";
        let result = extract_line(buf, 4096);
        assert!(result.is_some());
        let (line, consumed, truncated) = result.unwrap();
        assert_eq!(line, b"USER anon");
        assert_eq!(consumed, 10);
        assert!(!truncated);
    }

    #[test]
    fn test_extract_line_incomplete() {
        let buf = b"USER anon";
        let result = extract_line(buf, 4096);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_line_truncated() {
        let buf = b"USER anon\r\n";
        let result = extract_line(buf, 4); // max_len=4
        assert!(result.is_some());
        let (line, _consumed, truncated) = result.unwrap();
        assert_eq!(line, b"USER");
        assert!(truncated);
    }

    #[test]
    fn test_port_parsers() {
        let port = ftp_active_port(b"PORT 192,168,0,13,234,10");
        assert_eq!(port, Ok((&b""[..], 59914)));

        let port = ftp_pasv_response(
            b"227 Entering Passive Mode (212,27,32,66,221,243).",
        );
        assert_eq!(port, Ok((&b""[..], 56819)));

        let port = ftp_epsv_response(
            b"229 Entering Extended Passive Mode (|||48758|).",
        );
        assert_eq!(port, Ok((&b""[..], 48758)));

        let port = ftp_active_eprt(
            b"EPRT |2|2a01:e34:ee97:b130:8c3e:45ea:5ac6:e301|41813|",
        );
        assert_eq!(port, Ok((&b""[..], 41813)));
    }

    #[test]
    fn test_parse_request_auth_tls() {
        let (_, req) = parse_request_line(b"AUTH TLS").unwrap();
        assert!(matches!(req.command, FtpRequestCommand::FTP_COMMAND_AUTH_TLS));
        assert_eq!(req.command_name, b"AUTH");
        assert_eq!(req.arg, Some(b"TLS".as_ref()));
    }

    #[test]
    fn test_parse_request_auth_tls_lowercase() {
        let (_, req) = parse_request_line(b"auth tls").unwrap();
        assert!(matches!(req.command, FtpRequestCommand::FTP_COMMAND_AUTH_TLS));
    }

    #[test]
    fn test_parse_request_auth_other_is_unknown() {
        let (_, req) = parse_request_line(b"AUTH GSSAPI").unwrap();
        assert!(matches!(req.command, FtpRequestCommand::FTP_COMMAND_UNKNOWN));
    }
}
