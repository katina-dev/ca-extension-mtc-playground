# MTC Verifier as a C Shared Library (for wolfSSL/C consumers)

**Status**: design note, not implemented. Saved 2026-05-03 for future work.

## Goal

Expose this repo's MTC inclusion-proof verifier as a C-callable shared library so a non-Go program (e.g. a wolfSSL-based service in C/C++) can verify MTC certificates in-process without spawning the `mtc-verify-cert` binary.

The verification math itself is small (`internal/merkle`, `internal/mtcformat`, `internal/mtccert`); this note captures how to package it for cross-language use without rewriting it.

## Approach

`go build -buildmode=c-shared` produces a `.so`/`.dylib` plus a generated `.h` header. Consumers `dlopen`/link against it like any other native library.

A small Go shim package exports the verification entry points using cgo's `//export` directive. Because cgo can only export top-level Go funcs in `package main`, the shim lives in its own `cmd/` directory.

## Prerequisite: move packages out of `internal/`

The Go shim must `import` the verifier code. Today it lives under `internal/`, which Go's build system blocks from external import — but the shim is still inside this module, so technically it could import them as-is. The clean move is still recommended so external consumers can also use the Go API directly:

```
internal/merkle    → pkg/merkle
internal/mtcformat → pkg/mtcformat
internal/mtccert   → pkg/mtccert
internal/cosigner  → pkg/cosigner   (verify side; sign side can stay internal)
```

Mechanically: `git mv` then `git grep -l 'internal/merkle' | xargs sed -i 's|internal/merkle|pkg/merkle|g'` (repeat per package). About one hour with tests.

## Shim layout

```
cmd/mtc-verify-lib/
  main.go        # cgo exports, package main
```

### Skeleton

```go
package main

/*
#include <stdlib.h>
#include <stdint.h>
*/
import "C"

import (
    "encoding/json"
    "unsafe"

    "github.com/<fork>/ca-extension-merkle/pkg/mtccert"
    "github.com/<fork>/ca-extension-merkle/pkg/merkle"
)

// MTCVerifyResult is the C-visible result struct (mirror in the .h).
type MTCVerifyResult struct {
    ProofValid         C.int
    LeafIndex          C.long
    SubtreeStart       C.long
    SubtreeEnd         C.long
    SignaturesVerified C.int
    Mode               *C.char // "signed" or "signatureless", caller frees
    Error              *C.char // NULL if ok, otherwise caller frees
}

// MTCVerifyCert verifies an MTC-spec certificate against optional landmarks.
//
// Inputs:
//   certDER, certLen           — DER-encoded cert bytes
//   landmarkRoot, landmarkLen  — 32-byte SHA-256 root (NULL to skip the
//                                landmark cross-check; only structural
//                                proof verification is performed)
//   landmarkSize               — tree size that landmarkRoot anchors
//
// Returns: pointer to MTCVerifyResult allocated with C.malloc; caller must
// MTCFreeResult() it (which also frees the .Mode/.Error C strings).
//
//export MTCVerifyCert
func MTCVerifyCert(
    certDER *C.char, certLen C.int,
    landmarkRoot *C.char, landmarkLen C.int,
    landmarkSize C.long,
) *MTCVerifyResult {
    cert := C.GoBytes(unsafe.Pointer(certDER), certLen)

    opts := mtccert.VerifyOptions{}
    if landmarkRoot != nil && landmarkLen == merkle.HashSize {
        var root merkle.Hash
        copy(root[:], C.GoBytes(unsafe.Pointer(landmarkRoot), landmarkLen))
        opts.Landmarks = map[int64]merkle.Hash{int64(landmarkSize): root}
    }

    res, err := mtccert.VerifyMTCCert(cert, opts)

    out := (*MTCVerifyResult)(C.malloc(C.size_t(unsafe.Sizeof(MTCVerifyResult{}))))
    if err != nil {
        out.Error = C.CString(err.Error())
        out.ProofValid = 0
        return out
    }
    out.ProofValid = boolToInt(res.ProofValid)
    out.LeafIndex = C.long(res.LeafIndex)
    out.SubtreeStart = C.long(res.SubtreeStart)
    out.SubtreeEnd = C.long(res.SubtreeEnd)
    out.SignaturesVerified = C.int(res.SignaturesVerified)
    out.Mode = C.CString(res.Mode)
    out.Error = nil
    return out
}

//export MTCFreeResult
func MTCFreeResult(r *MTCVerifyResult) {
    if r == nil { return }
    if r.Mode != nil  { C.free(unsafe.Pointer(r.Mode)) }
    if r.Error != nil { C.free(unsafe.Pointer(r.Error)) }
    C.free(unsafe.Pointer(r))
}

// Optional: a JSON-output convenience for consumers that prefer string parsing
// over the struct.
//
//export MTCVerifyCertJSON
func MTCVerifyCertJSON(certDER *C.char, certLen C.int,
                        optionsJSON *C.char) *C.char {
    cert := C.GoBytes(unsafe.Pointer(certDER), certLen)
    var opts mtccert.VerifyOptions
    if optionsJSON != nil {
        _ = json.Unmarshal([]byte(C.GoString(optionsJSON)), &opts)
    }
    res, err := mtccert.VerifyMTCCert(cert, opts)
    if err != nil {
        return C.CString(`{"ok":false,"error":"` + err.Error() + `"}`)
    }
    b, _ := json.Marshal(res)
    return C.CString(string(b))
}

func boolToInt(b bool) C.int { if b { return 1 }; return 0 }

func main() {} // required for c-shared
```

## Build

```bash
go build -buildmode=c-shared \
  -o lib/libmtcverify.so \
  ./cmd/mtc-verify-lib/
```

Produces:
- `lib/libmtcverify.so` (Linux) — about 5–10 MB; embeds the Go runtime and GC
- `lib/libmtcverify.h` — auto-generated, contains `MTCVerifyResult`, `MTCVerifyCert`, `MTCFreeResult`, `MTCVerifyCertJSON`

For macOS use `-o lib/libmtcverify.dylib`. For Windows `-buildmode=c-shared` produces a `.dll` plus an import lib.

## Consumer side (C with wolfSSL)

```c
#include "libmtcverify.h"
#include <wolfssl/wolfcrypt/sha256.h>

int verify_cert(const uint8_t *cert_der, size_t cert_len,
                const uint8_t *trusted_root, int64_t tree_size) {
    MTCVerifyResult *r = MTCVerifyCert(
        (char*)cert_der, (int)cert_len,
        (char*)trusted_root, 32,
        tree_size);
    if (r->Error != NULL) {
        fprintf(stderr, "verify error: %s\n", r->Error);
        MTCFreeResult(r);
        return -1;
    }
    int ok = (r->ProofValid != 0);
    MTCFreeResult(r);
    return ok;
}
```

Linker flags: `-L./lib -lmtcverify -Wl,-rpath,./lib`

## Where the trusted root comes from

`MTCVerifyCert` only does structural verification when `landmarkRoot == NULL` —
it confirms the cert + proof are internally consistent but does NOT compare
against a trusted tree state. For real verification the caller must supply the
trusted `(tree_size, root)` pair, typically from a cosigned checkpoint.

The wolfSSL consumer can verify the checkpoint itself with wolfSSL's primitives:
- Parse the C2SP signed-note format (text)
- Verify the cosigner's Ed25519 or ML-DSA signature line with wolfSSL
  (wolfSSL has both as of recent FIPS 140-3 PQC builds)
- Extract `tree_size` and `root_hash` from the body
- Pass to `MTCVerifyCert` as `landmarkSize` / `landmarkRoot`

This keeps the trust anchor entirely in code the consumer controls; the Go .so
is only doing the Merkle math. No bridge contact required at verify time.

## Gotchas

1. **Embedded runtime size.** The .so is ~5–10 MB even though our verifier is
   tiny — that's the Go GC, scheduler, and stdlib. Acceptable for most servers,
   painful for embedded targets.
2. **Threading model.** Go's runtime spawns its own threads. Calling Go code
   from C is safe but the Go runtime initializes on first call; first call is
   slow (~milliseconds). Subsequent calls are sub-microsecond.
3. **Static linking is harder.** `-buildmode=c-shared` is dynamic. For static,
   use `-buildmode=c-archive` to get a `.a` file. Cleaner for single-binary
   deployments but the consumer's link step needs `-lpthread` on Linux.
4. **Cross-compilation.** Producing a Linux .so from macOS or vice versa
   requires `CGO_ENABLED=1` plus a cross C compiler (e.g. zig cc). Pre-build
   per target in CI rather than asking consumers to build.
5. **ABI stability.** Changing the `MTCVerifyResult` struct layout breaks all
   callers. Treat the .h as a published interface — additive only, version
   the .so soname (`libmtcverify.so.1`).
6. **`internal/` block.** The shim itself is inside this module so it could
   technically import `internal/...`, but moving the verifier packages to
   `pkg/` first makes the API officially public and unblocks pure-Go external
   consumers at the same time.

## Testing checklist

- [ ] Unit test in Go: round-trip a known cert + proof, confirm result matches
      `mtccert.VerifyMTCCert` directly.
- [ ] C test harness in `cmd/mtc-verify-lib/test/`: link against the .so, call
      with the same cert, confirm equivalent result.
- [ ] Memory leak check: run the C harness under valgrind verifying 10k certs
      with `MTCFreeResult` on each, confirm flat heap.
- [ ] Cross-validate against `bin/mtc-verify-cert` on the same cert — exit code
      and `MTCVerifyResult.ProofValid` must agree.

## When NOT to do this

- If verification volume is < 100/sec, subprocess (`bin/mtc-verify-cert`) is
  simpler and avoids the runtime weight.
- If the consumer is itself in Go (with `pkg/` exported), `import` the package
  directly — no cgo, no .so, no marshaling overhead.
- If the consumer is an embedded device where 5–10 MB is unacceptable, port
  the verification algorithm to C using wolfSSL primitives instead (~200 LOC,
  per the third option discussed in chat).

## Related files in this repo

- `internal/mtccert/verify.go` — the function being exported
- `internal/merkle/merkle.go` — pure Merkle math the shim depends on
- `internal/mtcformat/encoding.go` — TLS-presentation encoder
- `cmd/mtc-verify-cert/main.go` — existing CLI; same logic, different boundary
