// SPDX-FileCopyrightText: 2024 Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use std::str::FromStr;

use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::handles::KeyHandle;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm, SymmetricMode};
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{
    InitialValue, MaxBuffer, PublicBuilder, SymmetricCipherParameters, SymmetricDefinitionObject,
};
use tss_esapi::{structures::Auth, Context, TctiNameConf};

/// TPM Box error.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Error encountered while communicating with the TPM.
    TpmError(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {}

impl From<tss_esapi::Error> for Error {
    fn from(error: tss_esapi::Error) -> Self {
        Error::TpmError(error.to_string())
    }
}

type Result<T> = std::result::Result<T, Error>;

/// TPM encryption engine.
///
/// This object contains the ephemeral symmetric key used for encryption and decryption.
pub struct TpmBox {
    context: Context,
    symmetric_key_handle: KeyHandle,
    initial_value: InitialValue,
}

impl TpmBox {
    /// Constructs a new TPM encryption engine.
    pub fn new(tcti: &str) -> Result<Self> {
        let mut context = Context::new(TctiNameConf::from_str(tcti)?)?;

        context.tr_set_auth(Hierarchy::Null.into(), Auth::default())?;

        let primary_key_auth = Auth::try_from(context.get_random(16)?.as_ref().to_vec())?;

        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(true)
            .with_sign_encrypt(true)
            .with_restricted(false)
            .build()?;

        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::SymCipher)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_symmetric_cipher_parameters(SymmetricCipherParameters::new(
                SymmetricDefinitionObject::AES_256_CFB,
            ))
            .with_symmetric_cipher_unique_identifier(Default::default())
            .build()?;

        let symmetric_key_handle =
            context.execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.create_primary(
                    Hierarchy::Null,
                    public,
                    Some(primary_key_auth.clone()),
                    None,
                    None,
                    None,
                )
                .expect("Failed to create primary handle")
                .key_handle
            });
        context.tr_set_auth(symmetric_key_handle.into(), primary_key_auth)?;

        let initial_value = InitialValue::from_bytes(context.get_random(16)?.as_ref())?;

        Ok(Self {
            context,
            initial_value,
            symmetric_key_handle,
        })
    }

    /// IOs OK.
    fn encrypt_decrypt(
        &mut self,
        data: impl AsRef<[u8]>,
        decrypt: bool,
    ) -> Result<impl AsRef<[u8]>> {
        let data = MaxBuffer::from_bytes(data.as_ref())?;
        Ok(self
            .context
            .execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.encrypt_decrypt_2(
                    self.symmetric_key_handle,
                    decrypt,
                    SymmetricMode::Cfb,
                    data,
                    self.initial_value.clone(),
                )
            })?
            .0)
    }

    /// Encrypts a piece of data.
    pub fn encrypt(&mut self, data: impl AsRef<[u8]>) -> Result<impl AsRef<[u8]>> {
        self.encrypt_decrypt(data, false)
    }

    /// Decrypts a piece of data.
    pub fn decrypt(&mut self, data: impl AsRef<[u8]>) -> Result<impl AsRef<[u8]>> {
        self.encrypt_decrypt(data, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_unseal_works() -> testresult::TestResult {
        let mut data = TpmBox::new("mssim:")?;
        let plaintext = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 16];
        let ciphertext = data.encrypt(&plaintext)?;
        let unsealed = data.decrypt(&ciphertext)?;
        assert_eq!(plaintext, unsealed.as_ref());
        Ok(())
    }
}
