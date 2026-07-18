# example-plugin

Minimal PledgeGuard WASM plugin used to validate/demonstrate the plugin ABI.
Flags any line containing the literal substring `PLUGIN_SECRET`.

See `crates/pledgeguard-core/src/plugin.rs` for the full ABI documentation.

## Build

```sh
cargo build --release --target wasm32-unknown-unknown
```

Produces `target/wasm32-unknown-unknown/release/example_plugin.wasm`.

## Use

```sh
mkdir plugins
cp target/wasm32-unknown-unknown/release/example_plugin.wasm plugins/
cargo run -p pledgeguard-cli -- scan . --plugin-dir ./plugins
```

Note: this crate has its own `[workspace]` table so it is intentionally
*not* a member of the root PledgeGuard workspace (it targets `wasm32-unknown-unknown`
and is only ever built standalone).
