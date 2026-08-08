// Byte-literal scrubbing of secret values in a stream.
//
// Two properties matter and neither is free:
//
//   * Longest match wins. Secrets can overlap — a base URL plus token, or a
//     rotated key that shares a prefix with its predecessor. Taking the first
//     match in iteration order would redact the short secret and then emit the
//     rest of the long one verbatim.
//   * Only genuinely ambiguous bytes are held back. A secret can straddle two
//     reads, so some tail must be retained; but retaining a fixed
//     `max_secret_len - 1` bytes stalls interactive output for as long as it
//     takes to accumulate that many bytes. We retain only the longest suffix
//     that is actually a prefix of some secret — usually zero.

use std::io::{self, ErrorKind, Read, Write};

const REDACTED: &[u8] = b"[REDACTED]";
const READ_CHUNK: usize = 8192;

pub struct Scrubber {
    /// Secrets, longest first. Matching in this order makes the longest match win.
    secrets: Vec<Vec<u8>>,
    /// Longest secret length; bounds how much tail can ever be ambiguous.
    max_len: usize,
    /// Which bytes can begin a secret. Lets the copy loop skip the vast majority
    /// of offsets with one lookup instead of comparing against every secret.
    starts: [bool; 256],
}

impl Scrubber {
    pub fn new(secrets: &[Vec<u8>]) -> Scrubber {
        let mut secrets: Vec<Vec<u8>> = secrets.iter().filter(|s| !s.is_empty()).cloned().collect();
        // Longest first, then lexicographic so the ordering is deterministic
        // regardless of the caller's iteration order.
        secrets.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        secrets.dedup();
        let max_len = secrets.first().map(|s| s.len()).unwrap_or(0);
        let mut starts = [false; 256];
        for s in &secrets {
            starts[s[0] as usize] = true;
        }
        Scrubber { secrets, max_len, starts }
    }


    /// How many trailing bytes of `hay` must be held back because they could
    /// still grow into a secret on the next read.
    fn ambiguous_tail(&self, hay: &[u8]) -> usize {
        // A suffix at least as long as the longest secret cannot be a *proper*
        // prefix of anything, so it is never ambiguous.
        let window = (self.max_len.saturating_sub(1)).min(hay.len());
        // Longest partial match first: a shorter suffix that also matches would
        // flush bytes the longer candidate still needs.
        for len in (1..=window).rev() {
            let tail = &hay[hay.len() - len..];
            if !self.starts[tail[0] as usize] {
                continue;
            }
            if self.secrets.iter().any(|s| s.len() > len && s.starts_with(tail)) {
                return len;
            }
        }
        0
    }

    /// Scrub `src`, appending to `out`. Returns the number of trailing bytes of
    /// `src` left unprocessed because they are an ambiguous partial match.
    ///
    /// Coverage is the UNION of every secret occurrence, not a leftmost-longest
    /// walk. Overlapping secrets are the reason: with "AB" and "BCDEF" in
    /// "ABCDEF", consuming the "AB" match skips past the byte "BCDEF" starts at,
    /// and its tail would be emitted in the clear. A union cannot leak a byte
    /// that belongs to any secret.
    fn scrub_into(
        &self,
        src: &[u8],
        out: &mut Vec<u8>,
        cover: &mut Vec<bool>,
        at_eof: bool,
    ) -> usize {
        if self.secrets.is_empty() {
            out.extend_from_slice(src);
            return 0;
        }
        let hold = if at_eof { 0 } else { self.ambiguous_tail(src) };
        let end = src.len() - hold;

        cover.clear();
        cover.resize(src.len(), false);
        // A match may legitimately run past `end` into the held-back tail; those
        // bytes are then already decided and must not be held a second time.
        let mut limit = end;
        for i in 0..end {
            if !self.starts[src[i] as usize] {
                continue;
            }
            // Longest first, so the first hit at this offset covers the most.
            if let Some(len) = self.secrets.iter().find(|s| src[i..].starts_with(s)).map(|s| s.len())
            {
                cover[i..i + len].fill(true);
                limit = limit.max(i + len);
            }
        }

        let mut i = 0;
        while i < limit {
            let start = i;
            if cover[i] {
                while i < limit && cover[i] {
                    i += 1;
                }
                // One marker per contiguous run: adjacent secrets collapse into a
                // single [REDACTED] rather than advertising where one ends.
                out.extend_from_slice(REDACTED);
            } else {
                while i < limit && !cover[i] {
                    i += 1;
                }
                out.extend_from_slice(&src[start..i]);
            }
        }
        src.len() - limit
    }

    /// Stream `r` into `w`, redacting every secret occurrence.
    ///
    /// Write errors are returned rather than swallowed: when a downstream reader
    /// (`... | head -1`) closes the pipe, the relay must stop so the child
    /// process gets EPIPE instead of running forever against a reader that will
    /// never consume again.
    pub fn copy<R: Read, W: Write>(&self, r: &mut R, w: &mut W) -> io::Result<()> {
        let mut buf = vec![0u8; READ_CHUNK];
        let mut pending: Vec<u8> = Vec::with_capacity(READ_CHUNK);
        let mut out: Vec<u8> = Vec::with_capacity(READ_CHUNK + REDACTED.len());
        // Reused across reads; the coverage map is per-buffer, not per-stream.
        let mut cover: Vec<bool> = Vec::with_capacity(READ_CHUNK);

        loop {
            let n = match r.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                // EINTR is not end-of-stream. Treating it as one silently
                // truncates the child's output whenever a signal arrives.
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            pending.extend_from_slice(&buf[..n]);

            out.clear();
            let hold = self.scrub_into(&pending, &mut out, &mut cover, false);
            if !out.is_empty() {
                w.write_all(&out)?;
                w.flush()?;
            }
            // Keep only the ambiguous tail; drop what was emitted.
            let keep_from = pending.len() - hold;
            pending.drain(..keep_from);
        }

        out.clear();
        self.scrub_into(&pending, &mut out, &mut cover, true);
        if !out.is_empty() {
            w.write_all(&out)?;
        }
        w.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secrets(v: &[&str]) -> Vec<Vec<u8>> {
        v.iter().map(|s| s.as_bytes().to_vec()).collect()
    }

    /// Run the streaming path with a reader that hands over `chunk` bytes at a
    /// time, so straddling behaviour is actually exercised.
    fn stream(input: &str, secs: &[&str], chunk: usize) -> String {
        struct Chunked<'a> {
            data: &'a [u8],
            pos: usize,
            chunk: usize,
        }
        impl Read for Chunked<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let remaining = self.data.len() - self.pos;
                if remaining == 0 {
                    return Ok(0);
                }
                let n = remaining.min(self.chunk).min(buf.len());
                buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
                self.pos += n;
                Ok(n)
            }
        }
        let sc = Scrubber::new(&secrets(secs));
        let mut r = Chunked { data: input.as_bytes(), pos: 0, chunk };
        let mut w: Vec<u8> = Vec::new();
        sc.copy(&mut r, &mut w).unwrap();
        String::from_utf8(w).unwrap()
    }

    #[test]
    fn redacts_a_single_secret() {
        assert_eq!(stream("key=abc123!", &["abc123"], 4096), "key=[REDACTED]!");
    }

    #[test]
    fn passes_through_when_there_are_no_secrets() {
        assert_eq!(stream("nothing to hide", &[], 4096), "nothing to hide");
    }

    #[test]
    fn redacts_every_occurrence() {
        assert_eq!(stream("a S a S a", &["S"], 4096), "a [REDACTED] a [REDACTED] a");
    }

    /// The bug: with A a prefix of B, first-match-wins redacted A and emitted
    /// the remainder of B in the clear.
    #[test]
    fn longest_secret_wins_over_a_shorter_prefix() {
        assert_eq!(stream("x abc123xyz789 y", &["abc123", "abc123xyz789"], 4096), "x [REDACTED] y");
        // ... and in the other insertion order, since the old code depended on it.
        assert_eq!(stream("x abc123xyz789 y", &["abc123xyz789", "abc123"], 4096), "x [REDACTED] y");
    }

    /// Overlap rather than prefix: "AB" must not shadow "BCDEF".
    #[test]
    fn overlapping_secrets_do_not_leak_a_tail() {
        let out = stream("ABCDEF", &["AB", "BCDEF"], 4096);
        assert!(!out.contains("CDEF"), "leaked tail: {out}");
    }

    #[test]
    fn shorter_secret_still_redacted_on_its_own() {
        assert_eq!(stream("abc123 end", &["abc123", "abc123xyz789"], 4096), "[REDACTED] end");
    }

    #[test]
    fn catches_a_secret_split_across_reads() {
        for chunk in 1..=8 {
            assert_eq!(stream("pre-abc123-post", &["abc123"], chunk), "pre-[REDACTED]-post", "chunk={chunk}");
        }
    }

    #[test]
    fn catches_a_long_secret_split_bytewise() {
        let secret = "0123456789abcdef0123456789abcdef";
        let input = format!("head {secret} tail");
        assert_eq!(stream(&input, &[secret], 1), "head [REDACTED] tail");
    }

    /// The stall: output was withheld by `max_secret_len - 1` bytes regardless
    /// of content, so a short prompt sat invisible behind a long secret.
    #[test]
    fn does_not_withhold_bytes_that_cannot_start_a_secret() {
        let long = "X".repeat(4096);
        let sc = Scrubber::new(&secrets(&[&long]));
        let mut out = Vec::new();
        let held = sc.scrub_into(b"Password: ", &mut out, &mut Vec::new(), false);
        assert_eq!(held, 0, "held back bytes that cannot prefix the secret");
        assert_eq!(out, b"Password: ");
    }

    /// ... but a genuine partial match at the end IS held back, or the secret
    /// would slip through split across two reads.
    #[test]
    fn withholds_only_a_genuine_partial_match() {
        let sc = Scrubber::new(&secrets(&["SECRETVALUE"]));
        let mut out = Vec::new();
        let held = sc.scrub_into(b"noise SECRET", &mut out, &mut Vec::new(), false);
        assert_eq!(held, 6, "should hold exactly the partial match `SECRET`");
        assert_eq!(out, b"noise ");
    }

    /// At EOF nothing may be withheld, or the tail of the stream disappears.
    #[test]
    fn flushes_a_partial_match_at_eof() {
        assert_eq!(stream("noise SECRET", &["SECRETVALUE"], 4096), "noise SECRET");
    }

    #[test]
    fn write_errors_stop_the_relay() {
        // Models `... | head -1`: the reader is gone, so the relay must return
        // the error instead of draining the child forever.
        struct Closed;
        impl Write for Closed {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(ErrorKind::BrokenPipe, "closed"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        struct Endless;
        impl Read for Endless {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                buf.fill(b'y');
                Ok(buf.len())
            }
        }
        let sc = Scrubber::new(&secrets(&["s3cret"]));
        let err = sc.copy(&mut Endless, &mut Closed).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::BrokenPipe);
    }

    #[test]
    fn read_is_retried_after_eintr() {
        struct Interrupting {
            hits: usize,
        }
        impl Read for Interrupting {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.hits += 1;
                match self.hits {
                    1 => Err(io::Error::new(ErrorKind::Interrupted, "eintr")),
                    2 => {
                        let d = b"tail";
                        buf[..d.len()].copy_from_slice(d);
                        Ok(d.len())
                    }
                    _ => Ok(0),
                }
            }
        }
        let sc = Scrubber::new(&secrets(&["nope"]));
        let mut w = Vec::new();
        sc.copy(&mut Interrupting { hits: 0 }, &mut w).unwrap();
        assert_eq!(w, b"tail", "EINTR truncated the stream");
    }

    #[test]
    fn empty_and_duplicate_secrets_are_dropped() {
        let sc = Scrubber::new(&secrets(&["", "dup", "dup"]));
        assert_eq!(sc.secrets.len(), 1);
        assert!(!sc.secrets.is_empty());
        assert!(Scrubber::new(&secrets(&["", ""])).secrets.is_empty());
        // An empty secret must not match at every offset.
        assert_eq!(stream("abc", &[""], 4096), "abc");
    }

    #[test]
    fn binary_output_survives() {
        let sc = Scrubber::new(&secrets(&["KEY"]));
        let mut out = Vec::new();
        sc.scrub_into(&[0x00, 0xff, b'K', b'E', b'Y', 0xfe], &mut out, &mut Vec::new(), true);
        assert_eq!(out, [0x00, 0xff, b'[', b'R', b'E', b'D', b'A', b'C', b'T', b'E', b'D', b']', 0xfe]);
    }

    #[test]
    /// Adjacent secrets collapse into ONE marker. Emitting two would leak where
    /// the boundary between them falls.
    fn adjacent_secrets_collapse_into_one_redaction() {
        assert_eq!(stream("AABB", &["AA", "BB"], 4096), "[REDACTED]");
        // Separated secrets stay separate.
        assert_eq!(stream("AA BB", &["AA", "BB"], 4096), "[REDACTED] [REDACTED]");
    }
}
