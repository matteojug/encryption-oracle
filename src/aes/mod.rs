use aes::{cipher::consts::U12, Aes192};
use aes_gcm::{
    aead::{Aead, OsRng},
    Aes128Gcm, Aes256Gcm, AesGcm, Key, KeyInit, Nonce,
};
use generic_array::typenum::Unsigned;
use thiserror::Error;

pub mod api;

type Aes192Gcm = AesGcm<Aes192, U12>;

#[derive(Error, Debug, PartialEq, Clone)]
pub enum AesError {
    #[error("bad key len")]
    BadKeyLen,
    #[error("bad nonce len")]
    BadNonceLen,
    #[error("cryptographic error")]
    CryptoError,
}

#[derive(Debug)]
pub struct EncryptedPayload {
    pub key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

fn encrypt<T>(msg: &Vec<u8>, aad: Option<&Vec<u8>>) -> Result<EncryptedPayload, AesError>
where
    T: KeyInit + Aead,
{
    let key = T::generate_key(OsRng);
    let nonce = T::generate_nonce(OsRng);

    let cipher = T::new(&key);
    let mut ciphertext = cipher
        .encrypt(
            &nonce,
            aes_gcm::aead::Payload {
                msg,
                aad: aad.map_or(b"", |v| v.as_ref()),
            },
        )
        .map_err(|_| AesError::CryptoError)?;
    // aes_gcm implementation concat the tag to the chipertext
    let tag = ciphertext.split_off(ciphertext.len() - T::TagSize::to_usize());

    Ok(EncryptedPayload {
        key: key.to_vec(),
        nonce: nonce.to_vec(),
        ciphertext,
        tag,
    })
}

fn decrypt<T>(payload: &EncryptedPayload, aad: Option<&Vec<u8>>) -> Result<Vec<u8>, AesError>
where
    T: KeyInit + Aead,
{
    if payload.key.len() != T::key_size() {
        return Err(AesError::BadKeyLen);
    }
    let key: &Key<T> = payload.key.as_slice().into();

    if payload.nonce.len() != T::NonceSize::to_usize() {
        return Err(AesError::BadNonceLen);
    }
    let nonce: &Nonce<T::NonceSize> = payload.nonce.as_slice().into();

    // aes_gcm implementation concat the tag to the chipertext
    let msg = [payload.ciphertext.as_slice(), payload.tag.as_slice()].concat();

    let cipher = T::new(key);
    cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: msg.as_ref(),
                aad: aad.map_or(b"", |v| v.as_ref()),
            },
        )
        .map_err(|_| AesError::CryptoError)
}

pub fn encrypt_aes_128_gcm(
    data: &Vec<u8>,
    aad: Option<&Vec<u8>>,
) -> Result<EncryptedPayload, AesError> {
    encrypt::<Aes128Gcm>(data, aad)
}

pub fn decrypt_aes_128_gcm(
    payload: &EncryptedPayload,
    aad: Option<&Vec<u8>>,
) -> Result<Vec<u8>, AesError> {
    decrypt::<Aes128Gcm>(payload, aad)
}

pub fn encrypt_aes_192_gcm(
    data: &Vec<u8>,
    aad: Option<&Vec<u8>>,
) -> Result<EncryptedPayload, AesError> {
    encrypt::<Aes192Gcm>(data, aad)
}

pub fn decrypt_aes_192_gcm(
    payload: &EncryptedPayload,
    aad: Option<&Vec<u8>>,
) -> Result<Vec<u8>, AesError> {
    decrypt::<Aes192Gcm>(payload, aad)
}

pub fn encrypt_aes_256_gcm(
    data: &Vec<u8>,
    aad: Option<&Vec<u8>>,
) -> Result<EncryptedPayload, AesError> {
    encrypt::<Aes256Gcm>(data, aad)
}

pub fn decrypt_aes_256_gcm(
    payload: &EncryptedPayload,
    aad: Option<&Vec<u8>>,
) -> Result<Vec<u8>, AesError> {
    decrypt::<Aes256Gcm>(payload, aad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use once_cell::sync::Lazy;
    use test_case::test_case;
    use trait_set::trait_set;

    trait_set! {
        trait E = Fn(&Vec<u8>, Option<&Vec<u8>>) -> Result<EncryptedPayload, AesError>;
        trait D = Fn(&EncryptedPayload, Option<&Vec<u8>>) -> Result<Vec<u8>, AesError>;
    }

    const PLAINTEXT: Lazy<Vec<u8>> = Lazy::new(|| b"foobar \x00\x01\x02\x03".to_vec());

    #[test_case(encrypt_aes_128_gcm, decrypt_aes_128_gcm, 128)]
    #[test_case(encrypt_aes_192_gcm, decrypt_aes_192_gcm, 192)]
    #[test_case(encrypt_aes_256_gcm, decrypt_aes_256_gcm, 256)]
    fn happy(fn_enc: impl E, fn_dec: impl D, key_size: usize) {
        let enc = fn_enc(&PLAINTEXT, None).unwrap();
        assert_eq!(enc.key.len() * 8, key_size);
        let dec = fn_dec(&enc, None).unwrap();
        assert_eq!(*PLAINTEXT, dec);

        let another_enc = fn_enc(&PLAINTEXT, None).unwrap();
        assert_ne!(enc.nonce, another_enc.nonce);
        let another_dec = fn_dec(&another_enc, None).unwrap();
        assert_eq!(*PLAINTEXT, another_dec);
    }

    #[test_case(encrypt_aes_128_gcm, decrypt_aes_128_gcm)]
    #[test_case(encrypt_aes_192_gcm, decrypt_aes_192_gcm)]
    #[test_case(encrypt_aes_256_gcm, decrypt_aes_256_gcm)]
    fn wrong_key(fn_enc: impl E, fn_dec: impl D) {
        let mut enc = fn_enc(&PLAINTEXT, None).unwrap();
        let dec = fn_dec(&enc, None).unwrap();
        assert_eq!(*PLAINTEXT, dec);

        enc.key[0] ^= 1;
        assert_eq!(fn_dec(&enc, None).unwrap_err(), AesError::CryptoError);

        enc.key.pop();
        assert_eq!(fn_dec(&enc, None).unwrap_err(), AesError::BadKeyLen);
    }

    #[test_case(encrypt_aes_128_gcm, decrypt_aes_128_gcm)]
    #[test_case(encrypt_aes_192_gcm, decrypt_aes_192_gcm)]
    #[test_case(encrypt_aes_256_gcm, decrypt_aes_256_gcm)]
    fn wrong_nonce(fn_enc: impl E, fn_dec: impl D) {
        let mut enc = fn_enc(&PLAINTEXT, None).unwrap();
        let dec = fn_dec(&enc, None).unwrap();
        assert_eq!(*PLAINTEXT, dec);

        enc.nonce[0] ^= 1;
        assert_eq!(fn_dec(&enc, None).unwrap_err(), AesError::CryptoError);

        enc.nonce.pop();
        assert_eq!(fn_dec(&enc, None).unwrap_err(), AesError::BadNonceLen);
    }

    #[test_case(encrypt_aes_128_gcm, decrypt_aes_128_gcm)]
    #[test_case(encrypt_aes_192_gcm, decrypt_aes_192_gcm)]
    #[test_case(encrypt_aes_256_gcm, decrypt_aes_256_gcm)]
    fn aad(fn_enc: impl E, fn_dec: impl D) {
        let aad = b"some aad \x00\x01\x02\x03".to_vec();
        let mut another_aad = aad.clone();
        another_aad.push(42);

        let enc = fn_enc(&PLAINTEXT, Some(&aad)).unwrap();
        assert_eq!(fn_dec(&enc, Some(&aad)).unwrap(), *PLAINTEXT);
        assert_eq!(fn_dec(&enc, None).unwrap_err(), AesError::CryptoError);
        assert_eq!(
            fn_dec(&enc, Some(&another_aad)).unwrap_err(),
            AesError::CryptoError
        );

        let enc = fn_enc(&PLAINTEXT, None).unwrap();
        assert_eq!(fn_dec(&enc, None).unwrap(), *PLAINTEXT);
        assert_eq!(fn_dec(&enc, Some(&aad)).unwrap_err(), AesError::CryptoError);
    }
}
