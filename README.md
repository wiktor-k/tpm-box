# TPM Box

Encrypts data to a ephemeral symmetric key that is stored in the TPM.

This way the application can store and give others encrypted blobs that can be decrypted only by the same application process.

There are two primary use cases:

## Temporary seal

Sealing data and then unsealing it using the same in-memory object:

```rust
# fn main() -> testresult::TestResult {
let mut data = tpm_box::TpmBox::new("device:/dev/tpmrm0")?;
let plaintext = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 16];
let ciphertext = data.encrypt(&plaintext)?;
let unsealed = data.decrypt(&ciphertext)?;
assert_eq!(plaintext, unsealed.as_ref());
# Ok(()) }
```
