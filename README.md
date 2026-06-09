# OpenVPN 2.x UDP Obfuscation

A small set of patches that add an `obfuscate-udp` directive to **OpenVPN 2.x**
(developed and verified against the `release/2.7` branch). It wraps every UDP
datagram in a keyed, pseudo-random transform so the traffic no longer carries a
recognizable OpenVPN payload signature.

The patch sits **below** the OpenVPN protocol layer, in the link read/write
path, so it works transparently in both **tun** and **tap** mode and on both
the **client** and the **server**.

> **Status:** working — handshake + tunnel verified end-to-end.
> **Crypto backend:** OpenSSL only (uses EVP, RAND and SHA).

## Prebuilt client

Don't want to build it yourself? A ready-to-run, patched OpenVPN client (and the
full patched source as a fork) is available here:

**https://github.com/aw3r1se/ovpn-obfuscate-udp** — see the
[Releases](https://github.com/aw3r1se/ovpn-obfuscate-udp/releases) page for the
prebuilt Windows binary.

---

## What's in this repo

```
ovpn_patches/
├── README.md
├── 0001-obfs-add-UDP-obfuscation-module-obfs_udp.c-.h.patch
├── 0002-obfs-integrate-UDP-obfuscation-into-the-link-read-wr.patch
└── 0003-obfs-parse-the-obfuscate-udp-config-directive.patch
```

- **0001** adds the obfuscation engine (`src/openvpn/obfs_udp.c` / `.h`).
- **0002** hooks it into `forward.c` (obfuscate just before the UDP write,
  deobfuscate right after the read) and enlarges the buffer tailroom in
  `init.c` for the padding.
- **0003** parses the `obfuscate-udp <key> <padding>` config directive in
  `options.c`.

---

## How it works

Each UDP datagram is transformed in four phases on send and reversed on
receive:

1. **Padding** — random padding bounded by a keyed marker byte. Data packets
   (opcode 6/9) may get none; control packets are force-padded so the total is
   at least 32 bytes. The boundary marker is `marker_byte ^ (total_len % 0xFF)`,
   chained by XOR through the padding bytes.
2. **32-bit XOR cascade** — multiplier `0xCC9E2D51`; the 32-bit key is XOR'd
   into the **last** word, then each word is mixed with the word to its right.
3. **AES-128-XTS** over the head of the packet — `tweak`/IV = the **last 16
   bytes** of the datagram (never themselves encrypted). 16 bytes are encrypted
   for data packets (opcode 6/9, total ≥ 48), otherwise `total − 16` bytes.
4. **64-bit XOR cascade** — multiplier `0x87C37B91114253D5`.

Everything is keyed off a 64-byte shared secret, so the bytes on the wire look
pseudo-random and contain no fixed OpenVPN signature.

### Key schedule

The 64-byte key is split into two independent 32-byte halves:

- **send** (obfuscate) uses `key[0..31]`
- **receive** (deobfuscate) uses `key[32..63]`

For each half: the AES-128-XTS key is the raw 32 bytes; the padding marker byte
is `SHA256(half)[0]`; the 32-bit XOR key is `SHA256(half)[1..4]` (native LE).

Because the two directions use different halves, **the two peers must use
swapped halves relative to each other:**

- **Client:** `obfuscate-udp AABB <padding>`
- **Server:** `obfuscate-udp BBAA <padding>` (same key, halves swapped)

(`A` = the first 32 bytes, `B` = the last 32 bytes.) Both endpoints must run a
build with this patch; it is **not** wire-compatible with stock OpenVPN.

### Architecture

- `src/openvpn/obfs_udp.c` / `.h` — the obfuscation engine (one context per
  link socket; AES-128-XTS via OpenSSL EVP).
- Hooks live in `src/openvpn/forward.c`: `process_outgoing_link()` obfuscates
  just before the UDP write, `read_incoming_link()` deobfuscates right after the
  read. The same `struct link_socket` (one `obfs_udp` context) is shared by the
  server's top context and every per-client instance, so client and tap
  **server** are both covered.
- `frame_finalize_options()` enlarges the buffer tailroom for the padding (at
  least 32 bytes, since short control packets are force-padded).
- The `obfuscate-udp <key> <padding>` directive is parsed in `options.c`.

---

## Step 1: Get a clean OpenVPN 2.x tree

```bash
git clone https://github.com/OpenVPN/openvpn.git
cd openvpn
git checkout release/2.7
```

## Step 2: Apply the patches

```bash
git am /path/to/ovpn_patches/*.patch
```

If you don't want commits, just the file changes:

```bash
git apply /path/to/ovpn_patches/*.patch
```

### Verify

```bash
git log --oneline -3
#   obfs: parse the obfuscate-udp config directive
#   obfs: integrate UDP obfuscation into the link read/write path
#   obfs: add UDP obfuscation module (obfs_udp.c/.h)
ls src/openvpn/obfs_udp.c src/openvpn/obfs_udp.h
```

## Step 3: Build

`obfs_udp.c` is wired into both `Makefile.am` and `CMakeLists.txt`. The
obfuscation needs an **OpenSSL** build.

### 3a. Linux / *BSD / macOS (autotools)

```bash
sudo apt-get update
sudo apt-get install -y build-essential autoconf automake libtool pkg-config \
    liblzo2-dev liblz4-dev libssl-dev libpam0g-dev libcap-ng-dev libnl-genl-3-dev

autoreconf -i -v -f
./configure --with-crypto-library=openssl
make -j"$(nproc)"
```

Smoke test (use a 128-hex key and a non-zero padding):

```bash
echo 'obfuscate-udp 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff 100' > /tmp/t.conf
./src/openvpn/openvpn --config /tmp/t.conf --verb 3 --mode p2p --dev null 2>&1 | grep -i obfs
# expect: OBFS: UDP obfuscation initialized (padding=100)
```

### 3b. Windows (CMake + vcpkg + Visual Studio)

Three gotchas to know:

1. **Generator must match your installed VS.** The stock `win-amd64-release`
   preset uses generator "Visual Studio 17 2022". If your C++ toolset is in
   Visual Studio 2026, add a `CMakeUserPresets.json` that inherits it and
   overrides the generator to "Visual Studio 18 2026" (run
   `cmake --list-presets` to confirm CMake knows that generator), and make sure
   the VS you target has the **Desktop development with C++** workload.
2. **Use a real git clone of vcpkg**, not the one bundled inside Visual Studio.
   The bundled copy has no `.git` and rejects OpenVPN's manifest with
   "requires a manifest with a specified baseline".
3. **Put the Windows SDK `bin` on PATH** so `mc.exe` (the message compiler) is
   found, otherwise `openvpnserv` fails configure with "No message compiler
   found." (Or build from a Developer prompt — but that overrides `VCPKG_ROOT`
   to the bundled vcpkg, re-triggering gotcha #2, so prefer setting PATH
   manually.)

```powershell
git clone https://github.com/microsoft/vcpkg.git C:\vcpkg
C:\vcpkg\bootstrap-vcpkg.bat
$env:VCPKG_ROOT = "C:\vcpkg"
$env:PATH = "C:\Program Files (x86)\Windows Kits\10\bin\<sdk-version>\x64;" + $env:PATH

# from the patched tree
cmake --preset win-amd64-release          # or your VS2026 preset
cmake --build --preset win-amd64-release
```

vcpkg builds OpenSSL/LZO/LZ4 on the first configure (slow once, cached after).
The resulting `openvpn.exe` is under `out\build\<preset>\Release\`.

### 3c. Windows cross-compiled from Linux (MinGW)

```bash
export VCPKG_ROOT=$PWD/../vcpkg
cmake --preset mingw-x64
cmake --build --preset mingw-x64
# output: out/build/mingw/x64/Release/
```

> The CMake build defaults to `-Werror`. If your toolchain flags something
> unrelated, relax it with `-DUSE_WERROR=OFF`.

---

## Step 4: Configure

Add to **both** the client and server config:

```
obfuscate-udp <key> <padding>
disable-dco
```

```
remote <server> <port>
proto  udp
```

> **`disable-dco` is required.** The obfuscation hooks live in OpenVPN's
> userspace link path (`forward.c`). DCO (Data Channel Offload) moves packet
> I/O into the kernel driver (`ovpn-dco-win` / `ovpn-dco`), **bypassing** those
> hooks — the TLS handshake then stalls after the first exchange because
> subsequent packets go out un-obfuscated. DCO is on by default on Windows 2.7
> builds whenever the driver is present, so it can switch on silently between
> builds. Always set `disable-dco` (or build without DCO).

- **key**: exactly 128 hex characters (= 64 bytes). The first 32 bytes drive
  the send direction, the last 32 the receive direction (see the key schedule
  above). The peer must use the swapped halves.
- **padding**: integer 1..1500 — the maximum random padding added per packet.
  **Do not use 0**: short control packets must reach 32 bytes for the cipher, so
  a too-small padding budget breaks the handshake. Values like `32`–`200` work
  well.

On startup you should see:

```
OBFS: UDP obfuscation initialized (padding=32)
```

Per-packet failures (key mismatch, etc.) log at the link level, e.g.:

```
OBFS: unobfuscate_udp() has failed
```

A mismatch drops every packet and the TLS handshake times out after ~60 s.

---

## Disclaimer

Provided as-is, for research, interoperability and educational purposes. You are
responsible for complying with the laws and the terms of service that apply to
you. The authors take no responsibility for how it is used.
