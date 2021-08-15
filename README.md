# brainkey
A minimalist key stretcher

# Building

Just use `cargo build --release` but to make a fully static
binary use musl:

```
cargo build --release --target x86_64-unknown-linux-musl
strip target/x86_64-unknown-linux-musl/release/brainkey
```

# musl

Musl can be installed from a snapshot at
https://git.musl-libc.org/cgit/musl
And then
`./configure && make install`

Path needs to be updated to include /usr/local/musl/bin (or you move the binary somewhere else).
Then run

`rustup target add x86_64-unknown-linux-musl`
