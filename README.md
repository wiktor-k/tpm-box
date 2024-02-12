<!--
# SPDX-FileCopyrightText: 2024 Wiktor Kwapisiewicz <wiktor@metacode.biz>
# SPDX-License-Identifier: CC0-1.0
-->
# TPM Box

[![CI](https://github.com/wiktor-k/tpm-box/actions/workflows/ci.yml/badge.svg)](https://github.com/wiktor-k/tpm-box/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/tpm-box)](https://crates.io/crates/tpm-box)

Encrypts data to a ephemeral symmetric key that is stored in the TPM.

This way the application can store and give others encrypted blobs that can be decrypted only by the same instance of the `TpmBox`.

## Example

Sealing the data and then unsealing it using the same in-memory object:

```rust
let mut data = tpm_box::TpmBox::new("mssim:").unwrap();

let plaintext = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 16];

let ciphertext = data.encrypt(&plaintext).unwrap();
let unsealed = data.decrypt(&ciphertext).unwrap();

assert_eq!(plaintext, unsealed.as_ref());
```

For hardware TPMs a TCTI such as `device:/dev/tpmrm0` is appropriate.

## License

This project is licensed under either of:

  - [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0),
  - [MIT license](https://opensource.org/licenses/MIT).

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this crate by you, as defined in the
Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
