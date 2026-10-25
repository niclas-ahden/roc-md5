import Compress

## MD5 message digests (RFC 1321) in pure Roc.
##
## ```roc
## Md5.hash("abc".to_utf8()).to_hex() # "900150983cd24fb0d6963f7d28e17f72"
##
## Md5.empty()
##     .write("a".to_utf8())
##     .write("bc".to_utf8())
##     .finish()
##     .to_hex() # the same digest
## ```
##
## An `Md5` value is an MD5 computation that takes its input in pieces, for
## data that arrives in chunks such as a file read a block at a time. Writing
## the pieces in order gives the digest of all of them together. It is an
## ordinary immutable value: `finish` does not use it up, and writing more to
## an earlier one branches off from that point.
##
## MD5 is broken as a cryptographic hash. Anyone can make two inputs with the
## same digest in seconds on a laptop, so it must not be what decides trust:
## not for signatures, certificates, password storage or telling apart files
## that someone else chose.
Md5 :: { state : Compress.State, pending : List(U8), length : U64 }.{

	## A 16-byte MD5 digest.
	Digest :: { bytes : List(U8) }.{

		## The 16 raw bytes.
		to_bytes : Digest -> List(U8)
		to_bytes = |digest| digest.bytes

		## The 32 lowercase hexadecimal characters `md5sum` prints.
		to_hex : Digest -> Str
		to_hex = |digest| Str.from_utf8_lossy(digest.bytes.fold(List.with_capacity(32), |hex, byte| hex.append(hex_digit(byte.shr_zf_wrap(4))).append(hex_digit(byte.bitwise_and(0x0F)))))

		## A digest from exactly 16 raw bytes.
		from_bytes : List(U8) -> Try(Digest, DigestBytesErr)
		from_bytes = |bytes|
			if bytes.len() == digest_bytes {
				# A copy when `bytes` has spare capacity or is a slice of a
				# longer list, which the digest would otherwise keep alive.
				Ok(Digest.{ bytes: bytes.release_excess_capacity() })
			} else {
				Err(WrongLength({ expected: digest_bytes, actual: bytes.len() }))
			}

		## A digest from exactly 32 ASCII hexadecimal characters. Uppercase and
		## lowercase are accepted, a `0x` prefix is not. The length and the
		## `InvalidHex` index count bytes, and the index is that of the first
		## byte that is not a hex digit.
		from_hex : Str -> Try(Digest, DigestHexErr)
		from_hex = |text| {
			chars = text.to_utf8()
			if chars.len() != 2 * digest_bytes {
				Err(WrongLength({ expected: 2 * digest_bytes, actual: chars.len() }))
			} else {
				var $bytes = List.with_capacity(digest_bytes)
				var $index = 0
				while $index < chars.len() {
					high = nibble_at(chars, $index)?
					low = nibble_at(chars, $index + 1)?
					$bytes = $bytes.append(high.shl_wrap(4).bitwise_or(low))
					$index = $index + 2
				}
				Ok(Digest.{ bytes: $bytes })
			}
		}

		## Whether both digests hold the same bytes. This is what `==` runs.
		##
		## Like any list comparison it can stop at the first difference, so
		## how long it takes can tell someone how much of a digest they got
		## right. That is harmless for checksums and other public digests. To
		## check a secret one against input someone else controls, compare
		## them as `Hmac` values from
		## [roc-hmac](https://github.com/niclas-ahden/roc-hmac), whose `==` is safe
		## against timing attacks.
		is_eq : Digest, Digest -> Bool
		is_eq = |left, right| left.bytes == right.bytes

		## Feed the digest into Roc's non-cryptographic hasher, so a digest
		## can be a `Dict` key or a `Set` element.
		to_hash : Digest, hasher -> hasher where [hasher.write_bytes : hasher, List(U8) -> hasher]
		to_hash = |digest, hasher| hasher.write_bytes(digest.bytes)

		## `Md5.Digest("…")` with the hex digest, for `Str.inspect` and `dbg`.
		to_inspect : Digest -> Str
		to_inspect = |digest| "Md5.Digest(\"${digest.to_hex()}\")"
	}

	## Why [Md5.Digest.from_bytes] refused its input.
	DigestBytesErr : [WrongLength({ expected : U64, actual : U64 })]

	## Why [Md5.Digest.from_hex] refused its input.
	DigestHexErr : [WrongLength({ expected : U64, actual : U64 }), InvalidHex({ index : U64, byte : U8 })]

	## An MD5 computation that has seen no input.
	empty : () -> Md5
	empty = || Md5.{ state: Compress.initial_state, pending: [], length: 0 }

	## Add bytes to the input.
	write : Md5, List(U8) -> Md5
	write = |md5, bytes| {
		length = md5.length.plus_wrap(bytes.len())
		# Room for a whole block, so one buffer takes the pending bytes from
		# write to write. It is allocated on the first write, and copied when
		# an earlier computation still uses it. The bytes after the last whole
		# block are always copied into it, never kept as a slice of `bytes`,
		# which would keep everything written alive.
		#
		# `room` has a name of its own because reading `md5.pending` again
		# inside the `reserve` call makes the buffer look shared, and
		# `reserve` then copies it on every write.
		room = block_bytes - md5.pending.len()
		pending = md5.pending.reserve(room)
		if pending.len() + bytes.len() < block_bytes {
			Md5.{ state: md5.state, pending: pending.append_sublist(bytes, { start: 0, len: bytes.len() }), length }
		} else if pending.is_empty() {
			absorb(md5.state, pending, bytes, 0, length)
		} else {
			needed = block_bytes - pending.len()
			block = pending.append_sublist(bytes, { start: 0, len: needed })
			state = Compress.compress(md5.state, block, 0)
			absorb(state, block.clear(), bytes, needed, length)
		}
	}

	## The digest of everything written so far.
	finish : Md5 -> Digest
	finish = |md5| finish_with(md5.state, md5.pending, md5.length)

	## The MD5 digest of `bytes`.
	hash : List(U8) -> Digest
	hash = |bytes| {
		# Straight to the end rather than through `write`, which would copy
		# the bytes after the last whole block to keep them.
		absorbed = Compress.compress_all(Compress.initial_state, bytes, 0)
		finish_with(absorbed.state, bytes.drop_first(absorbed.offset), bytes.len())
	}

	## The MD5 digest of byte chunks taken in order, the same as [Md5.hash] of
	## them concatenated.
	hash_chunks : Iter(List(U8)) -> Digest
	hash_chunks = |chunks| chunks.fold(Md5.empty(), Md5.write).finish()
}

digest_bytes = 16

block_bytes = Compress.block_bytes

## Compress the whole blocks of `bytes` from `offset` on, and copy the bytes
## after the last whole block into `buffer`, which is empty and has room for
## them, for the next write.
absorb : Compress.State, List(U8), List(U8), U64, U64 -> Md5
absorb = |state, buffer, bytes, offset, length| {
	absorbed = Compress.compress_all(state, bytes, offset)
	rest = { start: absorbed.offset, len: bytes.len() - absorbed.offset }
	Md5.{ state: absorbed.state, pending: buffer.append_sublist(bytes, rest), length }
}

## The digest of an input whose whole blocks brought the registers to
## `state`, followed by `rest`, less than a block, `length` bytes in all.
##
## RFC 1321 section 3.1 and 3.2: a one bit, zeros up to 56 bytes into a
## block, then the length in bits as a little-endian 64-bit number. The tail
## is built in one allocation, since for a small input the allocations cost
## more than the hashing.
finish_with : Compress.State, List(U8), U64 -> Md5.Digest
finish_with = |state, rest, length| {
	fill = if rest.len() < 56 56 - rest.len() else 120 - rest.len()
	bits = length.shl_wrap(3)
	var $tail = rest.reserve(fill + 8).append_sublist(padding, { start: 0, len: fill })
	$tail = append_u32_le($tail, bits.to_u32_wrap())
	$tail = append_u32_le($tail, bits.shr_zf_wrap(32).to_u32_wrap())
	digest_of(Compress.compress_all(state, $tail, 0).state)
}

## The one bit and the zeros of the padding, as many as an input can need.
padding : List(U8)
padding = [0x80].concat(List.repeat(0, 63))

## The digest the registers hold at the end: A, B, C and D as little-endian
## bytes.
digest_of : Compress.State -> Md5.Digest
digest_of = |{ a, b, c, d }| {
	var $bytes = List.with_capacity(digest_bytes)
	$bytes = append_u32_le($bytes, a)
	$bytes = append_u32_le($bytes, b)
	$bytes = append_u32_le($bytes, c)
	$bytes = append_u32_le($bytes, d)
	Md5.Digest.{ bytes: $bytes }
}

## `bytes` with `value` appended as 4 little-endian bytes.
append_u32_le : List(U8), U32 -> List(U8)
append_u32_le = |bytes, value|
	bytes
		.append(value.to_u8_wrap())
		.append(value.shr_zf_wrap(8).to_u8_wrap())
		.append(value.shr_zf_wrap(16).to_u8_wrap())
		.append(value.shr_zf_wrap(24).to_u8_wrap())

## The lowercase hex digit for a value below 16.
hex_digit : U8 -> U8
hex_digit = |nibble| if nibble < 10 '0' + nibble else 'a' + nibble - 10

## The value of the hex digit at `index`. `from_hex` checks the length
## first, so an index past the end is a bug in this module.
nibble_at : List(U8), U64 -> Try(U8, Md5.DigestHexErr)
nibble_at = |chars, index| {
	byte = match chars.get(index) {
		Ok(value) => value
		Err(OutOfBounds) => {
			crash "Md5: read a hex digit at ${index.to_str()} of ${chars.len().to_str()} bytes"
		}
	}
	if byte >= '0' and byte <= '9' {
		Ok(byte - '0')
	} else if byte >= 'a' and byte <= 'f' {
		Ok(byte - 'a' + 10)
	} else if byte >= 'A' and byte <= 'F' {
		Ok(byte - 'A' + 10)
	} else {
		Err(InvalidHex({ index, byte }))
	}
}

# ---- Tests ----

## The hex digest of a string's UTF-8 bytes.
md5_hex : Str -> Str
md5_hex = |text| Md5.hash(text.to_utf8()).to_hex()

## `count` bytes counting up from 0, wrapping at 256.
counting : U64 -> List(U8)
counting = |count| List.repeat(0, count).map_with_index(|_, index| index.to_u8_wrap())

## The hex digest of `count` counting bytes.
counting_hex : U64 -> Str
counting_hex = |count| Md5.hash(counting(count)).to_hex()

# RFC 1321 appendix A.5, the test suite.
expect md5_hex("") == "d41d8cd98f00b204e9800998ecf8427e"
expect md5_hex("a") == "0cc175b9c0f1b6a831c399e269772661"
expect md5_hex("abc") == "900150983cd24fb0d6963f7d28e17f72"
expect md5_hex("message digest") == "f96b697d7cb7938d525a2f31aaf161d0"
expect md5_hex("abcdefghijklmnopqrstuvwxyz") == "c3fcd3d76192e4007dfb496cca67e13b"
expect md5_hex("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") == "d174ab98d277d9f5a5611c2c9f419d9f"
expect md5_hex("12345678901234567890123456789012345678901234567890123456789012345678901234567890") == "57edf4a22be3c955ac49da2e2107b67a"

# The vectors below were computed with coreutils `md5sum`, an
# implementation independent of this one.

expect md5_hex("The quick brown fox jumps over the lazy dog") == "9e107d9d372bb6826bd81d3542a419d6"
expect md5_hex("The quick brown fox jumps over the lazy dog.") == "e4d909c290d0fb1ca068ffaddf22cbd0"

# Text is hashed as its UTF-8 bytes.
expect md5_hex("räksmörgås 🦀") == "6e9f5d1c0ec2db6696c3660a3e9b970b"

# The lengths around the padding. 55 bytes leave room for the length in
# their block and 56 do not, 64 fill a block exactly, and from 256 on every
# byte value is in the input.
expect counting_hex(1) == "93b885adfe0da089cdf634904fd59f71"
expect counting_hex(55) == "6912ee65fff2d9f9ce2508cddf8bcda0"
expect counting_hex(56) == "51fdd1acda72405dfdfa03fcb85896d7"
expect counting_hex(57) == "5320ef4c17ef34a0cf2db763338d25eb"
expect counting_hex(63) == "48a6295221902e8e0938f773a7185e72"
expect counting_hex(64) == "b2d3f56bc197fd985d5965079b5e7148"
expect counting_hex(65) == "8bd7053801c768420faf816fadba971c"
expect counting_hex(119) == "1c772251899a7ff007400b888d6b2042"
expect counting_hex(120) == "b7ba1efc6022e9ed272f00b8831e26e6"
expect counting_hex(121) == "b0b2d719a838db877b6d6571a39a1cdc"
expect counting_hex(127) == "8402b21e7bc7906493bae0dac017f1f9"
expect counting_hex(128) == "37eff01866ba3f538421b30b7cbefcac"
expect counting_hex(129) == "46f986692847558fc38b0cece591c20f"
expect counting_hex(255) == "11b7aaa64c413d2f0fccf893881c46a2"
expect counting_hex(256) == "e2c865db4162bed963bfaa9ef6ac18f0"
expect counting_hex(1000) == "cbecbdb0fdd5cec1e242493b6008cc79"

# A million bytes, 15,625 blocks.
expect md5_hex(Str.repeat("a", 1_000_000)) == "7707d6ae4e027c70eea2a935c2296f21"

# ---- The length field ----
#
# Inputs from 2^29 bytes on set the high half of the 64-bit length field,
# which none of the inputs above reach. So these hashers are built with such
# lengths and nothing pending, and compared with the block of padding RFC
# 1321 section 3.2 asks for, its length bytes written out by hand.

## The digest of the one block of padding after an input that ends on a
## block boundary: `0x80`, 55 zeros and the 8 bytes of `length_field`.
padding_digest : List(U8) -> Md5.Digest
padding_digest = |length_field| digest_of(Compress.compress(Compress.initial_state, [0x80].concat(List.repeat(0, 55)).concat(length_field), 0))

## A hasher that has seen `length` bytes, all of them in whole blocks.
hasher_after : U64 -> Md5
hasher_after = |length| Md5.{ state: Compress.initial_state, pending: [], length }

# The helper itself, on the empty input.
expect padding_digest([0, 0, 0, 0, 0, 0, 0, 0]) == Md5.hash([])

# 2^32 bytes are 2^35 bits, which only the high half of the field holds.
expect hasher_after(0x1_0000_0000).finish() == padding_digest([0, 0, 0, 0, 8, 0, 0, 0])

# 2^61 + 1 bytes are 2^64 + 8 bits, of which only the low 64 bits are kept.
expect hasher_after(0x2000_0000_0000_0001).finish() == padding_digest([8, 0, 0, 0, 0, 0, 0, 0])

# ---- Hashing in pieces ----

# 300 bytes split in two at every point give the digest of the whole. The
# splits leave every number of bytes pending, and whole blocks after them.
expect {
	bytes = counting(300)
	whole = Md5.hash(bytes)
	splits : List(U64)
	splits = List.from_iter((0..=300).iter())
	splits.all(|split| Md5.empty().write(bytes.take_first(split)).write(bytes.drop_first(split)).finish() == whole)
}

# One byte at a time.
expect {
	bytes = counting(200)
	bytes.fold(Md5.empty(), |hasher, byte| hasher.write([byte])).finish() == Md5.hash(bytes)
}

# Uneven pieces: shorter than a block, exactly a block, and several blocks
# that start with bytes pending.
expect {
	bytes = counting(1000)
	sizes : List(U64)
	sizes = [3, 61, 64, 1, 200, 7, 64, 600]
	written = sizes.fold(
		{ hasher: Md5.empty(), rest: bytes },
		|{ hasher, rest }, size| { hasher: hasher.write(rest.take_first(size)), rest: rest.drop_first(size) },
	)
	written.rest.is_empty() and written.hasher.finish() == Md5.hash(bytes)
}

# Empty writes change nothing.
expect Md5.empty().write([]).write("abc".to_utf8()).write([]).finish() == Md5.hash("abc".to_utf8())
expect Md5.empty().finish() == Md5.hash([])

# Finishing does not use a hasher up, and an earlier hasher branches off.
expect {
	ab = Md5.empty().write("ab".to_utf8())
	branches = [ab, ab.write("c".to_utf8()), ab.write("d".to_utf8())]
	branches.map(|hasher| hasher.finish()) == ["ab", "abc", "abd"].map(|text| Md5.hash(text.to_utf8()))
}

# The same with whole blocks already compressed and bytes pending.
expect {
	bytes = counting(150)
	start = Md5.empty().write(bytes.take_first(100))
	start.write(bytes.drop_first(100)).finish() == Md5.hash(bytes)
		and start.finish() == Md5.hash(bytes.take_first(100))
}

## `bytes` in a list with room for 1000.
with_room : List(U8) -> List(U8)
with_room = |bytes| bytes.fold(List.with_capacity(1000), |list, byte| list.append(byte))

# The pending bytes are kept in a buffer of their own with room for a block,
# not in what was written or a slice of it, whose capacity is its length.
# That holds with nothing pending before, and with bytes pending that an
# earlier hasher still uses, for writes shorter than a block and for writes
# that complete one. Each write gets a list of its own, since a list that is
# used again afterwards would be copied anyway and hide the difference.
expect {
	fresh = Md5.empty().write(with_room([10, 11]))
	start = Md5.empty().write(counting(10))
	branch = start.write(with_room([10, 11]))
	fresh_block = Md5.empty().write(with_room(counting(70)))
	branch_block = start.write(with_room(counting(80).drop_first(10)))
	written = [fresh, branch, fresh_block, branch_block]
	own_buffers = written.all(|hasher| hasher.pending.capacity() >= block_bytes and hasher.pending.capacity() < 1000)
	own_buffers and written.append(start).map(|hasher| hasher.finish()) == [[10, 11], counting(12), counting(70), counting(80), counting(10)].map(Md5.hash)
}

expect Md5.hash_chunks(["mess".to_utf8(), "age ".to_utf8(), [], "digest".to_utf8()].iter()).to_hex() == "f96b697d7cb7938d525a2f31aaf161d0"
expect Md5.hash_chunks([].iter()) == Md5.hash([])

# ---- Digests ----

abc : Md5.Digest
abc = Md5.hash("abc".to_utf8())

abc_bytes : List(U8)
abc_bytes = [0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72]

expect abc.to_bytes() == abc_bytes
expect Md5.Digest.from_bytes(abc_bytes) == Ok(abc)
expect Md5.Digest.from_bytes([]) == Err(WrongLength({ expected: 16, actual: 0 }))
expect Md5.Digest.from_bytes(abc_bytes.drop_last(1)) == Err(WrongLength({ expected: 16, actual: 15 }))
expect Md5.Digest.from_bytes(abc_bytes.append(0)) == Err(WrongLength({ expected: 16, actual: 17 }))

# A digest keeps its bytes in an allocation of their own, not in the spare
# capacity of the list it was made from.
expect {
	bytes = List.with_capacity(1000).append(0x90).concat(abc_bytes.drop_first(1))
	match Md5.Digest.from_bytes(bytes) {
		Ok(digest) => digest == abc and digest.bytes.capacity() < bytes.capacity()
		Err(_) => Bool.False
	}
}

expect Md5.Digest.from_hex("900150983cd24fb0d6963f7d28e17f72") == Ok(abc)
expect Md5.Digest.from_hex("900150983CD24FB0D6963F7D28E17F72") == Ok(abc)
expect Md5.Digest.from_hex("900150983Cd24Fb0d6963f7D28e17F72") == Ok(abc)
expect Md5.Digest.from_hex("") == Err(WrongLength({ expected: 32, actual: 0 }))
expect Md5.Digest.from_hex("900150983cd24fb0d6963f7d28e17f7") == Err(WrongLength({ expected: 32, actual: 31 }))
expect Md5.Digest.from_hex("0x900150983cd24fb0d6963f7d28e17f72") == Err(WrongLength({ expected: 32, actual: 34 }))
expect Md5.Digest.from_hex("g00150983cd24fb0d6963f7d28e17f72") == Err(InvalidHex({ index: 0, byte: 'g' }))
expect Md5.Digest.from_hex("900150983cd24fb0d6963f7d28e17f7 ") == Err(InvalidHex({ index: 31, byte: ' ' }))

# The length and the index count bytes, so "é" is two and its first byte is
# the one reported.
expect Md5.Digest.from_hex("900150983cd24fb0d6963f7d28e17fé") == Err(InvalidHex({ index: 30, byte: 0xC3 }))

# Every hex digit, in both cases.
expect
	Md5.Digest.from_hex("0123456789abcdefABCDEF0123456789").map_ok(|digest| digest.to_bytes())
		== Ok([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89])

## `from_hex` of 32 zeros with `byte` at `index`.
from_hex_with : U8, U64 -> Try(Md5.Digest, Md5.DigestHexErr)
from_hex_with = |byte, index| Md5.Digest.from_hex(Str.from_utf8_lossy(List.repeat('0', 32).set(index, byte) ?? []))

# The characters just outside each range of hex digits are refused, as the
# high and as the low half of a byte.
expect
	['/', ':', '@', 'G', '`', 'g'].all(
		|byte| from_hex_with(byte, 6) == Err(InvalidHex({ index: 6, byte })) and from_hex_with(byte, 7) == Err(InvalidHex({ index: 7, byte })),
	)

# Every digest makes the round trip through hex and bytes.
expect {
	digests = [0, 1, 55, 64, 1000].map(|count| Md5.hash(counting(count)))
	digests.all(|digest| Md5.Digest.from_hex(digest.to_hex()) == Ok(digest) and Md5.Digest.from_bytes(digest.to_bytes()) == Ok(digest))
}

expect abc == Md5.hash("abc".to_utf8())
expect abc != Md5.hash("abd".to_utf8())

# Digests that differ in the last byte only.
expect Md5.Digest.from_bytes(List.repeat(0, 16)) != Md5.Digest.from_bytes(List.repeat(0, 15).append(1))

expect Str.inspect(abc) == "Md5.Digest(\"900150983cd24fb0d6963f7d28e17f72\")"

# `to_hash` feeds the hasher the 16 bytes. The Dict and Set tests below
# cannot show that, since a hash that ignores the digest still finds every
# key, only slower.
expect {
	Recorder :: { written : List(U8) }.{
		write_bytes : Recorder, List(U8) -> Recorder
		write_bytes = |recorder, bytes| Recorder.{ written: recorder.written.concat(bytes) }
	}
	abc.to_hash(Recorder.{ written: [] }).written == abc_bytes
}

# Digests as Dict keys and Set elements.
expect Dict.empty().insert(abc, "abc").get(Md5.hash("abc".to_utf8())) == Ok("abc")
expect {
	seen = Set.empty().insert(abc).insert(Md5.hash([])).insert(Md5.hash("abc".to_utf8()))
	seen.len() == 2 and seen.contains(Md5.hash([]))
}
