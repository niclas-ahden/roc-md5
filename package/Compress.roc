## RFC 1321 section 3.3 and 3.4: the four registers and the compression of
## 64-byte blocks. `Md5.roc` does the buffering and the padding around them.
##
## The package does not expose this module, so none of it, `State`
## included, is a name other packages can use.
Compress :: [].{

	## The size of the blocks MD5 compresses.
	block_bytes : U64
	block_bytes = 64

	## RFC 1321 section 3.3.
	initial_state : State
	initial_state = { a: 0x67452301, b: 0xefcdab89, c: 0x98badcfe, d: 0x10325476 }

	## Compress every whole block of `bytes` from `offset` on. Also returns the
	## offset where the whole blocks ended.
	compress_all : State, List(U8), U64 -> { state : State, offset : U64 }
	compress_all = |state, bytes, offset| {
		var $state = state
		var $offset = offset
		while $offset + block_bytes <= bytes.len() {
			$state = compress($state, bytes, $offset)
			$offset = $offset + block_bytes
		}
		{ state: $state, offset: $offset }
	}

	## RFC 1321 section 3.4: process the 64-byte block at `offset`. The steps
	## are spelled out one per line, in the order and with the constants the
	## RFC gives.
	compress : State, List(U8), U64 -> State
	compress = |state, bytes, offset| {
		x0 = word(bytes, offset)
		x1 = word(bytes, offset + 4)
		x2 = word(bytes, offset + 8)
		x3 = word(bytes, offset + 12)
		x4 = word(bytes, offset + 16)
		x5 = word(bytes, offset + 20)
		x6 = word(bytes, offset + 24)
		x7 = word(bytes, offset + 28)
		x8 = word(bytes, offset + 32)
		x9 = word(bytes, offset + 36)
		x10 = word(bytes, offset + 40)
		x11 = word(bytes, offset + 44)
		x12 = word(bytes, offset + 48)
		x13 = word(bytes, offset + 52)
		x14 = word(bytes, offset + 56)
		x15 = word(bytes, offset + 60)

		var $a = state.a
		var $b = state.b
		var $c = state.c
		var $d = state.d

		# Round 1
		$a = ff($a, $b, $c, $d, x0, 7, 0xd76aa478)
		$d = ff($d, $a, $b, $c, x1, 12, 0xe8c7b756)
		$c = ff($c, $d, $a, $b, x2, 17, 0x242070db)
		$b = ff($b, $c, $d, $a, x3, 22, 0xc1bdceee)
		$a = ff($a, $b, $c, $d, x4, 7, 0xf57c0faf)
		$d = ff($d, $a, $b, $c, x5, 12, 0x4787c62a)
		$c = ff($c, $d, $a, $b, x6, 17, 0xa8304613)
		$b = ff($b, $c, $d, $a, x7, 22, 0xfd469501)
		$a = ff($a, $b, $c, $d, x8, 7, 0x698098d8)
		$d = ff($d, $a, $b, $c, x9, 12, 0x8b44f7af)
		$c = ff($c, $d, $a, $b, x10, 17, 0xffff5bb1)
		$b = ff($b, $c, $d, $a, x11, 22, 0x895cd7be)
		$a = ff($a, $b, $c, $d, x12, 7, 0x6b901122)
		$d = ff($d, $a, $b, $c, x13, 12, 0xfd987193)
		$c = ff($c, $d, $a, $b, x14, 17, 0xa679438e)
		$b = ff($b, $c, $d, $a, x15, 22, 0x49b40821)

		# Round 2
		$a = gg($a, $b, $c, $d, x1, 5, 0xf61e2562)
		$d = gg($d, $a, $b, $c, x6, 9, 0xc040b340)
		$c = gg($c, $d, $a, $b, x11, 14, 0x265e5a51)
		$b = gg($b, $c, $d, $a, x0, 20, 0xe9b6c7aa)
		$a = gg($a, $b, $c, $d, x5, 5, 0xd62f105d)
		$d = gg($d, $a, $b, $c, x10, 9, 0x02441453)
		$c = gg($c, $d, $a, $b, x15, 14, 0xd8a1e681)
		$b = gg($b, $c, $d, $a, x4, 20, 0xe7d3fbc8)
		$a = gg($a, $b, $c, $d, x9, 5, 0x21e1cde6)
		$d = gg($d, $a, $b, $c, x14, 9, 0xc33707d6)
		$c = gg($c, $d, $a, $b, x3, 14, 0xf4d50d87)
		$b = gg($b, $c, $d, $a, x8, 20, 0x455a14ed)
		$a = gg($a, $b, $c, $d, x13, 5, 0xa9e3e905)
		$d = gg($d, $a, $b, $c, x2, 9, 0xfcefa3f8)
		$c = gg($c, $d, $a, $b, x7, 14, 0x676f02d9)
		$b = gg($b, $c, $d, $a, x12, 20, 0x8d2a4c8a)

		# Round 3
		$a = hh($a, $b, $c, $d, x5, 4, 0xfffa3942)
		$d = hh($d, $a, $b, $c, x8, 11, 0x8771f681)
		$c = hh($c, $d, $a, $b, x11, 16, 0x6d9d6122)
		$b = hh($b, $c, $d, $a, x14, 23, 0xfde5380c)
		$a = hh($a, $b, $c, $d, x1, 4, 0xa4beea44)
		$d = hh($d, $a, $b, $c, x4, 11, 0x4bdecfa9)
		$c = hh($c, $d, $a, $b, x7, 16, 0xf6bb4b60)
		$b = hh($b, $c, $d, $a, x10, 23, 0xbebfbc70)
		$a = hh($a, $b, $c, $d, x13, 4, 0x289b7ec6)
		$d = hh($d, $a, $b, $c, x0, 11, 0xeaa127fa)
		$c = hh($c, $d, $a, $b, x3, 16, 0xd4ef3085)
		$b = hh($b, $c, $d, $a, x6, 23, 0x04881d05)
		$a = hh($a, $b, $c, $d, x9, 4, 0xd9d4d039)
		$d = hh($d, $a, $b, $c, x12, 11, 0xe6db99e5)
		$c = hh($c, $d, $a, $b, x15, 16, 0x1fa27cf8)
		$b = hh($b, $c, $d, $a, x2, 23, 0xc4ac5665)

		# Round 4
		$a = ii($a, $b, $c, $d, x0, 6, 0xf4292244)
		$d = ii($d, $a, $b, $c, x7, 10, 0x432aff97)
		$c = ii($c, $d, $a, $b, x14, 15, 0xab9423a7)
		$b = ii($b, $c, $d, $a, x5, 21, 0xfc93a039)
		$a = ii($a, $b, $c, $d, x12, 6, 0x655b59c3)
		$d = ii($d, $a, $b, $c, x3, 10, 0x8f0ccc92)
		$c = ii($c, $d, $a, $b, x10, 15, 0xffeff47d)
		$b = ii($b, $c, $d, $a, x1, 21, 0x85845dd1)
		$a = ii($a, $b, $c, $d, x8, 6, 0x6fa87e4f)
		$d = ii($d, $a, $b, $c, x15, 10, 0xfe2ce6e0)
		$c = ii($c, $d, $a, $b, x6, 15, 0xa3014314)
		$b = ii($b, $c, $d, $a, x13, 21, 0x4e0811a1)
		$a = ii($a, $b, $c, $d, x4, 6, 0xf7537e82)
		$d = ii($d, $a, $b, $c, x11, 10, 0xbd3af235)
		$c = ii($c, $d, $a, $b, x2, 15, 0x2ad7d2bb)
		$b = ii($b, $c, $d, $a, x9, 21, 0xeb86d391)

		{
			a: state.a.plus_wrap($a),
			b: state.b.plus_wrap($b),
			c: state.c.plus_wrap($c),
			d: state.d.plus_wrap($d),
		}
	}
}

## RFC 1321's four 32-bit registers A, B, C and D.
State : { a : U32, b : U32, c : U32, d : U32 }

## Round 1's step, with F(X,Y,Z) = XY v not(X) Z.
ff : U32, U32, U32, U32, U32, U8, U32 -> U32
ff = |a, b, c, d, x, s, t| step(b.bitwise_and(c).bitwise_or(b.bitwise_not().bitwise_and(d)), a, b, x, s, t)

## Round 2's step, with G(X,Y,Z) = XZ v Y not(Z).
gg : U32, U32, U32, U32, U32, U8, U32 -> U32
gg = |a, b, c, d, x, s, t| step(b.bitwise_and(d).bitwise_or(c.bitwise_and(d.bitwise_not())), a, b, x, s, t)

## Round 3's step, with H(X,Y,Z) = X xor Y xor Z.
hh : U32, U32, U32, U32, U32, U8, U32 -> U32
hh = |a, b, c, d, x, s, t| step(b.bitwise_xor(c).bitwise_xor(d), a, b, x, s, t)

## Round 4's step, with I(X,Y,Z) = Y xor (X v not(Z)).
ii : U32, U32, U32, U32, U32, U8, U32 -> U32
ii = |a, b, c, d, x, s, t| step(c.bitwise_xor(b.bitwise_or(d.bitwise_not())), a, b, x, s, t)

## `b + ((a + mixed + x + t) <<< s)`, every addition modulo 2^32.
step : U32, U32, U32, U32, U8, U32 -> U32
step = |mixed, a, b, x, s, t| {
	sum = a.plus_wrap(mixed).plus_wrap(x).plus_wrap(t)
	b.plus_wrap(sum.shl_wrap(s).bitwise_or(sum.shr_zf_wrap(32 - s)))
}

## The little-endian word at `offset`. The callers only ask for words inside
## a whole block, so a word past the end is a bug in this package.
word : List(U8), U64 -> U32
word = |bytes, offset|
	match U32.from_le_bytes(bytes, offset) {
		Ok(value) => value
		Err(OutOfBounds) => {
			crash "Md5: read a word at ${offset.to_str()} of ${bytes.len().to_str()} bytes"
		}
	}
