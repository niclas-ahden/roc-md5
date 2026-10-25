## Hash in one call and in pieces, check a digest that came from elsewhere,
## and answer PostgreSQL's `md5` password challenge.
## Run it with: roc examples/main.roc
app [main!] {
	pf: platform "https://github.com/roc-lang/basic-cli/releases/download/0.26.0/GddgvsGjiNXrHFW6au5i5dUDbTs8FinQdrgE2Gqmw53t.tar.zst",
	md5: "../package/main.roc",
}

import pf.Stdout
import md5.Md5

main! = |_args| {
	# In one call
	digest = Md5.hash("The quick brown fox jumps over the lazy dog".to_utf8())
	Stdout.line!("one call:  ${digest.to_hex()}")?

	# In pieces, as they arrive. Writing them in order gives the digest of
	# all of them together.
	pieces = ["The quick brown ", "fox jumps over ", "the lazy dog"]
	streamed = pieces.fold(Md5.Hasher.empty(), |hasher, piece| hasher.write(piece.to_utf8())).finish()
	Stdout.line!("in pieces: ${streamed.to_hex()}")?

	# A digest from elsewhere, such as a line of an `md5sum` file
	expected = Md5.Digest.from_hex("9e107d9d372bb6826bd81d3542a419d6")?
	if streamed == expected {
		Stdout.line!("the checksum matches")?
	} else {
		Stdout.line!("the checksum does not match")?
	}

	# The server picks the salt, 4 random bytes
	answer = postgres_md5_password({ user: "postgres", password: "pencil", salt: [0x01, 0x02, 0x03, 0x04] })
	Stdout.line!("PostgreSQL password message: ${answer}")?

	Ok({})
}

## What a client answers PostgreSQL's `md5` password authentication with:
## "md5", then the hex MD5 of the hex MD5 of password and user name followed
## by the salt. PostgreSQL 18 deprecates this method, so prefer SCRAM-SHA-256
## where the server offers it.
postgres_md5_password : { user : Str, password : Str, salt : List(U8) } -> Str
postgres_md5_password = |{ user, password, salt }| {
	inner = Md5.hash(Str.concat(password, user).to_utf8()).to_hex()
	"md5${Md5.hash(inner.to_utf8().concat(salt)).to_hex()}"
}
