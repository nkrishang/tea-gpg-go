1. Sign hex message (e.g. `48656c6c6f2c20576f726c64` which is hex for "Hello, World" ) using gpg:

```bash
echo 48656c6c6f2c20576f726c64 | xxd -r -p | gpg --pinentry-mode loopback --detach-sign --armor
```

2. Export public key:

```bash
gpg --list-keys
```

```bash
gpg --export --armor <key-id>
```

Paste the hex message, armored public key and armored signature in `main.go`.
