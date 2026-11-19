## Description

<!-- Provide a concise summary of the change, fix, or new capability. -->

## Type of Change

- [ ] Bug fix (fix:)
- [ ] New feature (feat:)
- [ ] Documentation update (docs:)
- [ ] Refactoring (refactor:)
- [ ] Test or CI enhancement (test: / ci:)

## Cryptographic & Quality Checklist

- [ ] Uses Go standard library and vetted golang.org/x/crypto primitives only (zero homegrown crypto).
- [ ] Passes go vet ./..., GOOS=windows go vet ./..., and go test -race -count=1 ./... cleanly.
- [ ] Sensitive buffers are zeroized with WipeBytes and page-locked where applicable.
- [ ] Preserves SHUNA1/SHUNAS1 wire invariants, AlgID-first GCM zero-padding checks, and exit codes 0..4.
- [ ] Documentation stays concise without inline backtick clutter or unicode em dashes.
