build-custom:
    cargo build --release --no-default-features --features rt-custom

gt-custom-mars: build-custom
    cargo run --bin golden-tests --release -- --test-name fullmars

gt-custom: build-custom
    cargo run --bin golden-tests --release
