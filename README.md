# roc-md5

MD5 message digests (RFC 1321) in pure Roc.

See the documentation at [https://niclas-ahden.github.io/roc-md5/](https://niclas-ahden.github.io/roc-md5/).

## Usage

```roc
app [main!] {
	pf: platform "https://github.com/roc-lang/basic-cli/releases/download/0.23.0/GNN5tt2gKdX4dhawg4915C4YB193woHFdcCkz31fhGxv.tar.zst",
	md5: "https://github.com/niclas-ahden/roc-md5/releases/download/0.1.0/qtnfgJ4Cys1MRonJBNztb83tiWbDn8peonUvaKWXhe4.tar.zst",
}

import pf.Stdout
import md5.Md5

main! = |_args| {
	# In one call
	digest = Md5.hash("The quick brown fox jumps over the lazy dog".to_utf8())
	Stdout.line!(digest.to_hex())? # 9e107d9d372bb6826bd81d3542a419d6

	# In pieces, such as a file read a block at a time
	streamed =
		Md5.Hasher.empty()
			.write("The quick brown ".to_utf8())
			.write("fox jumps over the lazy dog".to_utf8())
			.finish()

	# A digest from elsewhere, such as a line of an md5sum file
	expected = Md5.Digest.from_hex("9e107d9d372bb6826bd81d3542a419d6")?
	if streamed == expected {
		Stdout.line!("the checksum matches")?
	} else {
		Stdout.line!("the checksum does not match")?
	}

	Ok({})
}
```

## When to use MD5

MD5 is broken as a cryptographic hash which means you shouldn't use it for security, signatures, certificates etc. However, it's still useful for non-security-related uses such as creating checksums to catch accidental corruption in files and transfers.

## Limitations

- The input is whole bytes. RFC 1321 also defines digests of bit strings whose length is not a multiple of 8.
- No HMAC-MD5. To authenticate messages, use HMAC-SHA-256 from [roc-hmac](https://github.com/niclas-ahden/roc-hmac).

## Tests

The tests hold RFC 1321's test suite and digests computed with coreutils `md5sum`, an implementation independent of this one. They cover every input length around the padding (55, 56, 57, 63, 64 and 65 bytes, and the same one block longer), every byte value, a million bytes, lengths that need the high half of the 64-bit length field, input split in two at every point, one byte at a time and in uneven pieces, and parsing digests from hex and bytes, including the characters just outside each range of hex digits.
