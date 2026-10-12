# Byte-oriented string helpers for ASCII delimiters.
#
# Nutcracker's `lang.string` has no split/indexOf/startsWith and array/byte
# slices (`x[a ... b]`) are unsupported, so scanning and cutting is done on
# raw UTF-8 bytes. Splitting on an ASCII delimiter is always valid UTF-8 —
# ASCII bytes never occur inside a multi-byte sequence.
#
# NOTE: `source` is a reserved word in the Nutcracker parser; avoid it as
# an identifier.

# Returns the byte offset of the first occurrence of `needle` in `subject`, or -1.
public isolated function indexOf(string subject, string needle) returns int {
    byte[] subjectBytes = subject.toBytes();
    byte[] needleBytes = needle.toBytes();
    int needleLength = needleBytes.length();
    if needleLength == 0 {
        return 0;
    }
    int subjectLength = subjectBytes.length();
    if needleLength > subjectLength {
        return -1;
    }
    foreach int i in 0 ..< (subjectLength - needleLength + 1) {
        boolean matched = true;
        foreach int j in 0 ..< needleLength {
            if subjectBytes[i + j] != needleBytes[j] {
                matched = false;
                break;
            }
        }
        if matched {
            return i;
        }
    }
    return -1;
}

# Returns true when `subject` starts with `prefix`.
public isolated function hasPrefix(string subject, string prefix) returns boolean {
    byte[] subjectBytes = subject.toBytes();
    byte[] prefixBytes = prefix.toBytes();
    if prefixBytes.length() > subjectBytes.length() {
        return false;
    }
    foreach int j in 0 ..< prefixBytes.length() {
        if subjectBytes[j] != prefixBytes[j] {
            return false;
        }
    }
    return true;
}

# Returns `subject` without `prefix`, or an error when the prefix is absent.
public isolated function stripPrefix(string subject, string prefix) returns string|error {
    if !hasPrefix(subject, prefix) {
        return error("prefix not found: " + prefix);
    }
    return check string:fromBytes(sliceBytes(
            data = subject.toBytes(),
            startOffset = prefix.toBytes().length(),
            endOffset = subject.toBytes().length()));
}

# Splits `subject` on every occurrence of `delim`. Consecutive and trailing
# delimiters yield empty segments (same as Go's `strings.Split`).
public isolated function splitOn(string subject, string delim) returns string[]|error {
    string[] segments = [];
    if delim.length() == 0 {
        segments.push(subject);
        return segments;
    }
    byte[] subjectBytes = subject.toBytes();
    byte[] delimBytes = delim.toBytes();
    int delimLength = delimBytes.length();
    int subjectLength = subjectBytes.length();
    int segmentStart = 0;
    int cursor = 0;
    while cursor <= subjectLength - delimLength {
        boolean matched = true;
        foreach int j in 0 ..< delimLength {
            if subjectBytes[cursor + j] != delimBytes[j] {
                matched = false;
                break;
            }
        }
        if matched {
            segments.push(check string:fromBytes(sliceBytes(
                    data = subjectBytes,
                    startOffset = segmentStart,
                    endOffset = cursor)));
            cursor = cursor + delimLength;
            segmentStart = cursor;
        } else {
            cursor = cursor + 1;
        }
    }
    segments.push(check string:fromBytes(sliceBytes(
            data = subjectBytes,
            startOffset = segmentStart,
            endOffset = subjectLength)));
    return segments;
}

# Copies `data[startOffset ... endOffset)` — the byte-slice syntax the
# Nutcracker parser does not support, implemented with a loop.
public isolated function sliceBytes(byte[] data, int startOffset, int endOffset) returns byte[] {
    byte[] result = [];
    foreach int i in startOffset ..< endOffset {
        result.push(data[i]);
    }
    return result;
}

# Decodes an unpadded base64url string (RFC 4648 §5: `-`/`_`, optional `=` padding).
public isolated function base64urlDecode(string encoded) returns byte[]|error {
    byte[] inputBytes = encoded.toBytes();
    byte[] convertedBytes = [];
    foreach byte b in inputBytes {
        // NOTE: compare as int — Nutcracker narrows `byte` after each `==`
        // literal comparison and a second byte comparison fails to type-check.
        int byteCode = b;
        if byteCode == 45 { // '-' (0x2d) → '+'
            convertedBytes.push(43);
        } else if byteCode == 95 { // '_' (0x5f) → '/'
            convertedBytes.push(47);
        } else {
            convertedBytes.push(b);
        }
    }
    int remainder = convertedBytes.length() % 4;
    if remainder == 1 {
        return error("invalid base64url length");
    }
    if remainder > 0 {
        foreach int _ in 0 ..< (4 - remainder) {
            convertedBytes.push(0x3d); // '=' padding
        }
    }
    return array:fromBase64(check string:fromBytes(convertedBytes));
}

# Encodes bytes as a lowercase hex string (for crypto:buildRsaPublicKey,
# which takes hex-encoded modulus/exponent from JWKS `n`/`e`).
public isolated function hexEncode(byte[] data) returns string {
    return data.toBase16();
}
