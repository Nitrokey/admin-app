use ctaphid_dispatch::types::Error;

#[cfg(feature = "se050")]
use embedded_hal::blocking::delay::DelayUs;
use iso7816::Status;
#[cfg(feature = "se050")]
use se050::{
    se050::{
        commands::{
            CreateSession, DeleteAll, DeleteSecureObject, EcdsaSign, EcdsaVerify, GetRandom,
            ReadIdList, ReadObject, VerifySessionUserId, WriteBinary, WriteEcKey, WriteUserId,
        },
        policies::{ObjectAccessRule, ObjectPolicyFlags, Policy, PolicySet},
        EcCurve, EcDsaSignatureAlgo, ObjectId, P1KeyType, ProcessSessionCmd, Se050Result,
    },
    t1::I2CForT1,
};
use trussed::types::Vec;

#[cfg(feature = "se050")]
use se050::se050::Se050;

#[cfg(feature = "se050")]
use hex_literal::hex;

pub trait RunTests {
    fn run_tests<const N: usize>(&mut self, _response: &mut Vec<u8, N>) -> Result<(), Error> {
        debug_now!("Default run tests");
        Err(Error::InvalidCommand)
    }

    fn run_tests_internal<const N: usize>(
        &mut self,
        _response: &mut Vec<u8, N>,
    ) -> Result<(), Status> {
        Err(Status::NotFound)
    }
}

#[cfg(feature = "se050")]
const BUFFER_LEN: usize = 1024;

#[cfg(feature = "se050")]
#[derive(Debug)]
#[repr(u8)]
enum Advance {
    Enable = 1,
    Random1,
    Random2,
    Random3,
    WriteUserId,
    CreateSession,
    VerifySessionUserId,
    DeleteAll,
    List,
    WriteBinary1,
    ReadBinary1,
    DeleteBinary1,
    WriteBinary2,
    ReadBinary2,
    DeleteBinary2,
    WriteBinary3,
    ReadBinary3,
    DeleteBinary3,
    CreateP256,
    ListP256,
    GenerateP256,
    EcDsaP256,
    VerifyP256,
    DeleteP256,
    CreateP521,
    GenerateP521,
    EcDsaP521,
    VerifyP521,
    DeleteP521,
    RecreationWriteUserId,
    RecreationWriteBinary,
    RecreationDeleteAttempt,
    RecreationDeleteUserId,
    RecreationRecreateUserId,
    RecreationCreateSession,
    RecreationAuthSession,
    RecreationDeleteAttack,
    Rsa2048Gen,
    Rsa2048Sign,
    Rsa2048Verify,
    Rsa2048Encrypt,
    Rsa2048Decrypt,
    Rsa2048Delete,
    Rsa3072Gen,
    Rsa3072Sign,
    Rsa3072Verify,
    Rsa3072Encrypt,
    Rsa3072Decrypt,
    Rsa3072Delete,
    Rsa4096Gen,
    Rsa4096Sign,
    Rsa4096Verify,
    Rsa4096Encrypt,
    Rsa4096Decrypt,
    Rsa4096Delete,
    SymmWrite,
    SymmEncryptOneShot,
    SymmDecryptOneShot,
    SymmEncryptCreate,
    SymmEncryptInit,
    SymmEncryptUpdate1,
    SymmEncryptUpdate2,
    SymmEncryptFinal,
    SymmEncryptDelete,
    SymmDecryptCreate,
    SymmDecryptInit,
    SymmDecryptUpdate1,
    SymmDecryptUpdate2,
    SymmDecryptFinal,
    SymmDecryptDelete,
    SymmDelete,
    MacWrite,
    MacSignOneShot,
    MacVerifyOneShot,
    MacSignCreate,
    MacSignInit,
    MacSignUpdate1,
    MacSignUpdate2,
    MacSignFinal,
    MacSignDelete,
    MacVerifyCreate,
    MacVerifyInit,
    MacVerifyUpdate1,
    MacVerifyUpdate2,
    MacVerifyFinal,
    MacVerifyDelete,
    MacDelete,
}

impl RunTests for () {}

#[cfg(feature = "se050")]
impl<Twi: I2CForT1, D: DelayUs<u32>> RunTests for Se050<Twi, D> {
    fn run_tests<const N: usize>(&mut self, response: &mut Vec<u8, N>) -> Result<(), Error> {
        debug_now!("Se050 run tests");
        match self.run_tests_internal(response) {
            Ok(()) => Ok(()),
            Err(err) => {
                response.push(0).ok();
                let sw: [u8; 2] = err.into();
                response.extend_from_slice(&sw).ok();
                Ok(())
            }
        }
    }
    fn run_tests_internal<const N: usize>(
        &mut self,
        response: &mut Vec<u8, N>,
    ) -> Result<(), Status> {
        let atr = self.enable()?;
        response
            .extend_from_slice(&[
                atr.major,
                atr.minor,
                atr.patch,
                atr.secure_box_major,
                atr.secure_box_minor,
            ])
            .ok();
        response.push(Advance::Enable as _).ok();
        run_get_random(self, response)?;
        run_factory_reset(self, response)?;
        run_list(self, response)?;
        run_binary(self, response)?;
        run_ecc(self, response)?;
        run_userid_recreation(self, response)?;
        run_rsa2048(self, response)?;
        run_rsa3072(self, response)?;
        run_rsa4096(self, response)?;
        run_symm(self, response)?;
        run_mac(self, response)?;
        Ok(())
    }
}

#[cfg(feature = "se050")]
fn run_get_random<Twi: I2CForT1, D: DelayUs<u32>, const N: usize>(
    se050: &mut Se050<Twi, D>,
    response: &mut Vec<u8, N>,
) -> Result<(), Status> {
    let mut buf = [b'a'; BUFFER_LEN];
    let lens = [1, 256, 800];
    let advance = [Advance::Random1, Advance::Random2, Advance::Random3];
    for (len, advance) in lens.into_iter().zip(advance) {
        let res = se050.run_command(
            &GetRandom {
                length: (len as u16).into(),
            },
            &mut buf,
        )?;
        response.push(advance as u8).ok();
        if res.data == &[b'a'; BUFFER_LEN][..len] {
            debug!("Failed to get random");
            response.extend_from_slice(&[0, 0, 0]).ok();
            return Ok(());
        }
    }
    Ok(())
}

#[cfg(feature = "se050")]
fn run_factory_reset<Twi: I2CForT1, D: DelayUs<u32>, const N: usize>(
    se050: &mut Se050<Twi, D>,
    response: &mut Vec<u8, N>,
) -> Result<(), Status> {
    let mut buf = [b'a'; BUFFER_LEN];
    let data = &hex!("31323334");

    se050.run_command(
        &WriteUserId {
            policy: None,
            max_attempts: None,
            object_id: ObjectId::FACTORY_RESET,
            data,
        },
        &mut buf,
    )?;
    response.push(Advance::WriteUserId as u8).ok();
    let session = se050.run_command(
        &CreateSession {
            object_id: ObjectId::FACTORY_RESET,
        },
        &mut buf,
    )?;
    response.push(Advance::CreateSession as u8).ok();

    se050.run_command(
        &ProcessSessionCmd {
            session_id: session.session_id,
            apdu: VerifySessionUserId { user_id: data },
        },
        &mut buf,
    )?;
    response.push(Advance::VerifySessionUserId as u8).ok();

    se050.run_command(
        &ProcessSessionCmd {
            session_id: session.session_id,
            apdu: DeleteAll {},
        },
        &mut buf,
    )?;
    response.push(Advance::DeleteAll as u8).ok();
    Ok(())
}

#[cfg(feature = "se050")]
fn run_list<Twi: I2CForT1, D: DelayUs<u32>, const N: usize>(
    se050: &mut Se050<Twi, D>,
    response: &mut Vec<u8, N>,
) -> Result<(), Status> {
    let mut buf = [0; 200];
    se050.run_command(
        &ReadIdList {
            offset: 0.into(),
            filter: se050::se050::SecureObjectFilter::All,
        },
        &mut buf,
    )?;
    response.push(Advance::List as u8).ok();
    Ok(())
}

#[cfg(feature = "se050")]
fn run_binary<Twi: I2CForT1, D: DelayUs<u32>, const N: usize>(
    se050: &mut Se050<Twi, D>,
    response: &mut Vec<u8, N>,
) -> Result<(), Status> {
    let mut buf = [b'a'; 400];
    let buf2 = [b'b'; 400];
    let object_id = ObjectId(hex!("01020304"));
    let policy = &[Policy {
        object_id: ObjectId::INVALID,
        access_rule: ObjectAccessRule::from_flags(
            ObjectPolicyFlags::ALLOW_DELETE | ObjectPolicyFlags::ALLOW_READ,
        ),
    }];
    for (((len, advance_write), advance_read), advance_delete) in [1, 255, 300]
        .into_iter()
        .zip([
            Advance::WriteBinary1,
            Advance::WriteBinary2,
            Advance::WriteBinary3,
        ])
        .zip([
            Advance::ReadBinary1,
            Advance::ReadBinary2,
            Advance::ReadBinary3,
        ])
        .zip([
            Advance::DeleteBinary1,
            Advance::DeleteBinary2,
            Advance::DeleteBinary3,
        ])
    {
        se050.run_command(
            &WriteBinary {
                transient: false,
                policy: Some(PolicySet(policy)),
                object_id,
                offset: None,
                file_length: Some(len.into()),
                data: Some(&buf2[..len.into()]),
            },
            &mut buf,
        )?;
        response.push(advance_write as u8).ok();
        let res = se050.run_command(
            &ReadObject {
                object_id,
                offset: None,
                length: Some(len.into()),
                rsa_key_component: None,
            },
            &mut buf,
        )?;
        response.push(advance_read as u8).ok();
        if res.data[..len.into()] != buf2[..len.into()] {
            return Err(0x3001.into());
        }

        se050.run_command(&DeleteSecureObject { object_id }, &mut buf)?;
        response.push(advance_delete as u8).ok();
    }
    Ok(())
}

#[cfg(feature = "se050")]
fn run_ecc<Twi: I2CForT1, D: DelayUs<u32>, const N: usize>(
    se050: &mut Se050<Twi, D>,
    response: &mut Vec<u8, N>,
) -> Result<(), Status> {
    use se050::se050::commands::ReadEcCurveList;

    let mut buf = [0; 200];
    let mut buf2 = [0; 200];
    let object_id = ObjectId(hex!("01020304"));

    // *********** P256 *********** //

    se050.create_and_set_curve(EcCurve::NistP256)?;
    response.push(Advance::CreateP256 as u8).ok();
    let _res = se050.run_command(&ReadEcCurveList {}, &mut buf)?;
    debug_now!("Ec curves list: {:?}", _res);
    response.push(Advance::ListP256 as u8).ok();
    se050.run_command(
        &WriteEcKey {
            transient: false,
            is_auth: false,
            key_type: Some(P1KeyType::KeyPair),
            policy: None,
            max_attempts: None,
            object_id,
            curve: Some(EcCurve::NistP256),
            private_key: None,
            public_key: None,
        },
        &mut buf,
    )?;
    response.push(Advance::GenerateP256 as u8).ok();
    let res = se050.run_command(
        &EcdsaSign {
            key_id: object_id,
            data: &[52; 32],
            algo: EcDsaSignatureAlgo::Sha256,
        },
        &mut buf,
    )?;
    response.push(Advance::EcDsaP256 as u8).ok();
    let res = se050.run_command(
        &EcdsaVerify {
            key_id: object_id,
            data: &[52; 32],
            algo: EcDsaSignatureAlgo::Sha256,
            signature: res.signature,
        },
        &mut buf2,
    )?;
    if res.result != Se050Result::Success {
        return Err(0x3002.into());
    }
    response.push(Advance::VerifyP256 as u8).ok();
    se050.run_command(&DeleteSecureObject { object_id }, &mut buf)?;
    response.push(Advance::DeleteP256 as u8).ok();

    // *********** P521 *********** //

    se050.create_and_set_curve(EcCurve::NistP521)?;
    response.push(Advance::CreateP521 as u8).ok();
    se050.run_command(
        &WriteEcKey {
            transient: false,
            is_auth: false,
            key_type: Some(P1KeyType::KeyPair),
            policy: None,
            max_attempts: None,
            object_id,
            curve: Some(EcCurve::NistP521),
            private_key: None,
            public_key: None,
        },
        &mut buf,
    )?;
    response.push(Advance::GenerateP521 as u8).ok();
    let res = se050.run_command(
        &EcdsaSign {
            key_id: object_id,
            data: &[52; 64],
            algo: EcDsaSignatureAlgo::Sha512,
        },
        &mut buf,
    )?;
    response.push(Advance::EcDsaP521 as u8).ok();
    let res = se050.run_command(
        &EcdsaVerify {
            key_id: object_id,
            data: &[52; 64],
            algo: EcDsaSignatureAlgo::Sha512,
            signature: res.signature,
        },
        &mut buf2,
    )?;
    if res.result != Se050Result::Success {
        return Err(0x3003.into());
    }
    response.push(Advance::VerifyP521 as u8).ok();
    se050.run_command(&DeleteSecureObject { object_id }, &mut buf)?;
    response.push(Advance::DeleteP521 as u8).ok();
    Ok(())
}

#[cfg(feature = "se050")]
fn run_userid_recreation<Twi: I2CForT1, D: DelayUs<u32>, const N: usize>(
    se050: &mut Se050<Twi, D>,
    response: &mut Vec<u8, N>,
) -> Result<(), Status> {
    let mut buf = [0; BUFFER_LEN];
    let object_id = ObjectId(hex!("01020304"));
    let user_id = ObjectId(hex!("01223344"));
    let user_id_good_value = hex!("31323334");
    let user_id_bad_value = hex!("FFFFFFFF");
    let policy_user_id = &[Policy {
        object_id: ObjectId::INVALID,
        access_rule: ObjectAccessRule::from_flags(
            ObjectPolicyFlags::ALLOW_DELETE | ObjectPolicyFlags::ALLOW_WRITE,
        ),
    }];
    se050.run_command(
        &WriteUserId {
            policy: Some(PolicySet(policy_user_id)),
            max_attempts: None,
            object_id: user_id,
            data: &user_id_good_value,
        },
        &mut buf,
    )?;
    response.push(Advance::RecreationWriteUserId as u8).ok();
    let policy = &[Policy {
        object_id: user_id,
        access_rule: ObjectAccessRule::from_flags(
            ObjectPolicyFlags::ALLOW_DELETE | ObjectPolicyFlags::ALLOW_READ,
        ),
    }];
    se050.run_command(
        &WriteBinary {
            transient: false,
            policy: Some(PolicySet(policy)),
            object_id,
            offset: None,
            file_length: Some(2.into()),
            data: Some(&[1, 2]),
        },
        &mut buf,
    )?;
    response.push(Advance::RecreationWriteBinary as u8).ok();
    match se050.run_command(&DeleteSecureObject { object_id }, &mut buf) {
        Ok(_) => return Err(0x3004.into()),
        Err(se050::se050::Error::Status(Status::CommandNotAllowedNoEf)) => {}
        Err(_err) => {
            debug_now!("Got unexpected error: {_err:?}");
            return Err(0x3007.into());
        }
    }
    response.push(Advance::RecreationDeleteAttempt as u8).ok();
    se050.run_command(&DeleteSecureObject { object_id: user_id }, &mut buf)?;
    response.push(Advance::RecreationDeleteUserId as u8).ok();
    se050.run_command(
        &WriteUserId {
            policy: None,
            max_attempts: None,
            object_id: user_id,
            data: &user_id_bad_value,
        },
        &mut buf,
    )?;
    response.push(Advance::RecreationRecreateUserId as u8).ok();

    let session = se050.run_command(&CreateSession { object_id: user_id }, &mut buf)?;
    response.push(Advance::RecreationCreateSession as u8).ok();

    se050.run_command(
        &ProcessSessionCmd {
            session_id: session.session_id,
            apdu: VerifySessionUserId {
                user_id: &user_id_bad_value,
            },
        },
        &mut buf,
    )?;
    response.push(Advance::RecreationAuthSession as u8).ok();

    let attack = se050.run_command(
        &ProcessSessionCmd {
            session_id: session.session_id,
            apdu: DeleteSecureObject { object_id: user_id },
        },
        &mut buf,
    );

    match attack {
        Ok(_) => return Err(0x3005.into()),
        Err(se050::se050::Error::Status(Status::CommandNotAllowedNoEf)) => {}
        Err(_err) => {
            debug_now!("Got unexpected error: {_err:?}");
            return Err(0x3006.into());
        }
    }
    response.push(Advance::RecreationDeleteAttack as u8).ok();
    Ok(())
}

#[cfg(feature = "se050")]
fn run_rsa2048<Twi: I2CForT1, D: DelayUs<u32>, const N: usize>(
    se050: &mut Se050<Twi, D>,
    response: &mut Vec<u8, N>,
) -> Result<(), Status> {
    use se050::se050::{
        commands::{GenRsaKey, RsaDecrypt, RsaEncrypt, RsaSign, RsaVerify},
        RsaEncryptionAlgo, RsaSignatureAlgo,
    };

    let mut buf = [0; 1000];
    let mut buf2 = [0; 1000];
    let object_id = ObjectId(hex!("02334455"));
    se050.run_command(
        &GenRsaKey {
            transient: false,
            is_auth: false,
            policy: None,
            max_attempts: None,
            object_id,
            key_size: Some(2048.into()),
        },
        &mut buf,
    )?;
    response.push(Advance::Rsa2048Gen as u8).ok();
    let res = se050.run_command(
        &RsaSign {
            key_id: object_id,
            data: &[52; 32],
            algo: RsaSignatureAlgo::RsaSha256Pkcs1,
        },
        &mut buf,
    )?;
    response.push(Advance::Rsa2048Sign as u8).ok();
    let res = se050.run_command(
        &RsaVerify {
            key_id: object_id,
            data: &[52; 32],
            algo: RsaSignatureAlgo::RsaSha256Pkcs1,
            signature: res.signature,
        },
        &mut buf2,
    )?;
    response.push(Advance::Rsa2048Verify as u8).ok();
    let res = se050.run_command(
        &RsaEncrypt {
            key_id: object_id,
            plaintext: &[52; 32],
            algo: RsaEncryptionAlgo::Pkcs1,
        },
        &mut buf2,
    )?;
    response.push(Advance::Rsa2048Encrypt as u8).ok();
    let res = se050.run_command(
        &RsaDecrypt {
            key_id: object_id,
            algo: RsaEncryptionAlgo::Pkcs1,
            ciphertext: res.ciphertext,
        },
        &mut buf,
    )?;
    if res.plaintext != &[52; 32] {
        return Err(0x3008.into());
    }
    response.push(Advance::Rsa2048Decrypt as u8).ok();

    se050.run_command(&DeleteSecureObject { object_id }, &mut buf)?;
    response.push(Advance::Rsa2048Delete as u8).ok();

    Ok(())
}

#[cfg(feature = "se050")]
fn run_rsa3072<Twi: I2CForT1, D: DelayUs<u32>, const N: usize>(
    se050: &mut Se050<Twi, D>,
    response: &mut Vec<u8, N>,
) -> Result<(), Status> {
    use se050::se050::{
        commands::{GenRsaKey, RsaDecrypt, RsaEncrypt, RsaSign, RsaVerify},
        RsaEncryptionAlgo, RsaSignatureAlgo,
    };

    let mut buf = [0; 1000];
    let mut buf2 = [0; 1000];
    let object_id = ObjectId(hex!("02334455"));
    se050.run_command(
        &GenRsaKey {
            transient: false,
            is_auth: false,
            policy: None,
            max_attempts: None,
            object_id,
            key_size: Some(3072.into()),
        },
        &mut buf,
    )?;
    response.push(Advance::Rsa3072Gen as u8).ok();
    let res = se050.run_command(
        &RsaSign {
            key_id: object_id,
            data: &[52; 32],
            algo: RsaSignatureAlgo::RsaSha256Pkcs1,
        },
        &mut buf,
    )?;
    response.push(Advance::Rsa3072Sign as u8).ok();
    let res = se050.run_command(
        &RsaVerify {
            key_id: object_id,
            data: &[52; 32],
            algo: RsaSignatureAlgo::RsaSha256Pkcs1,
            signature: res.signature,
        },
        &mut buf2,
    )?;
    response.push(Advance::Rsa3072Verify as u8).ok();
    let res = se050.run_command(
        &RsaEncrypt {
            key_id: object_id,
            plaintext: &[52; 32],
            algo: RsaEncryptionAlgo::Pkcs1,
        },
        &mut buf2,
    )?;
    response.push(Advance::Rsa3072Encrypt as u8).ok();
    let res = se050.run_command(
        &RsaDecrypt {
            key_id: object_id,
            algo: RsaEncryptionAlgo::Pkcs1,
            ciphertext: res.ciphertext,
        },
        &mut buf,
    )?;
    if res.plaintext != &[52; 32] {
        return Err(0x3008.into());
    }
    response.push(Advance::Rsa3072Decrypt as u8).ok();

    se050.run_command(&DeleteSecureObject { object_id }, &mut buf)?;
    response.push(Advance::Rsa3072Delete as u8).ok();

    Ok(())
}

#[cfg(feature = "se050")]
fn run_rsa4096<Twi: I2CForT1, D: DelayUs<u32>, const N: usize>(
    se050: &mut Se050<Twi, D>,
    response: &mut Vec<u8, N>,
) -> Result<(), Status> {
    use se050::se050::{
        commands::{GenRsaKey, RsaDecrypt, RsaEncrypt, RsaSign, RsaVerify},
        RsaEncryptionAlgo, RsaSignatureAlgo,
    };

    let mut buf = [0; 1000];
    let mut buf2 = [0; 1000];
    let object_id = ObjectId(hex!("02334455"));
    se050.run_command(
        &GenRsaKey {
            transient: false,
            is_auth: false,
            policy: None,
            max_attempts: None,
            object_id,
            key_size: Some(4096.into()),
        },
        &mut buf,
    )?;
    response.push(Advance::Rsa4096Gen as u8).ok();
    let res = se050.run_command(
        &RsaSign {
            key_id: object_id,
            data: &[52; 32],
            algo: RsaSignatureAlgo::RsaSha256Pkcs1,
        },
        &mut buf,
    )?;
    response.push(Advance::Rsa4096Sign as u8).ok();
    let res = se050.run_command(
        &RsaVerify {
            key_id: object_id,
            data: &[52; 32],
            algo: RsaSignatureAlgo::RsaSha256Pkcs1,
            signature: res.signature,
        },
        &mut buf2,
    )?;
    response.push(Advance::Rsa4096Verify as u8).ok();
    let res = se050.run_command(
        &RsaEncrypt {
            key_id: object_id,
            plaintext: &[52; 32],
            algo: RsaEncryptionAlgo::Pkcs1,
        },
        &mut buf2,
    )?;
    response.push(Advance::Rsa4096Encrypt as u8).ok();
    let res = se050.run_command(
        &RsaDecrypt {
            key_id: object_id,
            algo: RsaEncryptionAlgo::Pkcs1,
            ciphertext: res.ciphertext,
        },
        &mut buf,
    )?;
    if res.plaintext != &[52; 32] {
        return Err(0x3008.into());
    }
    response.push(Advance::Rsa4096Decrypt as u8).ok();

    se050.run_command(&DeleteSecureObject { object_id }, &mut buf)?;
    response.push(Advance::Rsa4096Delete as u8).ok();

    Ok(())
}

#[cfg(feature = "se050")]
fn run_symm<Twi: I2CForT1, D: DelayUs<u32>, const N: usize>(
    se050: &mut Se050<Twi, D>,
    response: &mut Vec<u8, N>,
) -> Result<(), Status> {
    use se050::se050::{
        commands::{
            CipherDecryptInit, CipherEncryptInit, CipherFinal, CipherOneShotDecrypt,
            CipherOneShotEncrypt, CipherUpdate, CreateCipherObject, DeleteCryptoObj, WriteSymmKey,
        },
        CipherMode, CryptoObjectId, SymmKeyType,
    };

    let mut buf = [0; 1000];
    let mut buf2 = [0; 1000];
    let plaintext_data = [2; 32 * 15];
    let key_id = ObjectId(hex!("03445566"));
    let cipher_id = CryptoObjectId(hex!("0123"));
    let key = [0x42; 32];
    let iv = [0xFF; 16];
    se050.run_command(
        &WriteSymmKey {
            transient: true,
            is_auth: false,
            key_type: SymmKeyType::Aes,
            policy: None,
            max_attempts: None,
            object_id: key_id,
            kek_id: None,
            value: &key,
        },
        &mut buf,
    )?;
    response.push(Advance::SymmWrite as u8).ok();
    let ciphertext1 = se050.run_command(
        &CipherOneShotEncrypt {
            key_id,
            mode: CipherMode::AesCtr,
            plaintext: &plaintext_data,
            initialization_vector: Some(&iv),
        },
        &mut buf,
    )?;
    response.push(Advance::SymmEncryptOneShot as u8).ok();
    let plaintext1 = se050.run_command(
        &CipherOneShotDecrypt {
            key_id,
            mode: CipherMode::AesCtr,
            ciphertext: &ciphertext1.ciphertext,
            initialization_vector: Some(&iv),
        },
        &mut buf2,
    )?;
    response.push(Advance::SymmDecryptOneShot as u8).ok();
    assert_eq!(plaintext1.plaintext, plaintext_data);
    se050.run_command(
        &CreateCipherObject {
            id: cipher_id,
            subtype: CipherMode::AesCtr,
        },
        &mut buf2,
    )?;
    response.push(Advance::SymmEncryptCreate as u8).ok();
    se050.run_command(
        &CipherEncryptInit {
            key_id,
            initialization_vector: Some(&iv),
            cipher_id,
        },
        &mut buf2,
    )?;
    response.push(Advance::SymmEncryptInit as u8).ok();
    let ciphertext2 = se050.run_command(
        &CipherUpdate {
            cipher_id,
            data: &plaintext_data[0..32 * 10],
        },
        &mut buf2,
    )?;
    response.push(Advance::SymmEncryptUpdate1 as u8).ok();
    let ciphertext3 = se050.run_command(
        &CipherUpdate {
            cipher_id,
            data: &plaintext_data[32 * 10..][..32 * 5],
        },
        &mut buf2,
    )?;
    response.push(Advance::SymmEncryptUpdate2 as u8).ok();
    let ciphertext4 = se050.run_command(
        &CipherFinal {
            cipher_id,
            data: &plaintext_data[32 * 15..],
        },
        &mut buf2,
    )?;
    response.push(Advance::SymmEncryptFinal as u8).ok();
    se050.run_command(&DeleteCryptoObj { id: cipher_id }, &mut buf2)?;
    response.push(Advance::SymmEncryptDelete as u8).ok();
    se050.run_command(
        &CreateCipherObject {
            id: cipher_id,
            subtype: CipherMode::AesCtr,
        },
        &mut buf2,
    )?;
    response.push(Advance::SymmDecryptCreate as u8).ok();
    se050.run_command(
        &CipherDecryptInit {
            key_id,
            initialization_vector: Some(&iv),
            cipher_id,
        },
        &mut buf2,
    )?;
    response.push(Advance::SymmDecryptInit as u8).ok();
    let ciphertext2 = se050.run_command(
        &CipherUpdate {
            cipher_id,
            data: &ciphertext1.ciphertext[0..32 * 10],
        },
        &mut buf2,
    )?;
    response.push(Advance::SymmDecryptUpdate1 as u8).ok();
    let ciphertext3 = se050.run_command(
        &CipherUpdate {
            cipher_id,
            data: &ciphertext1.ciphertext[32 * 10..][..32 * 5],
        },
        &mut buf2,
    )?;
    response.push(Advance::SymmDecryptUpdate2 as u8).ok();
    let ciphertext4 = se050.run_command(
        &CipherFinal {
            cipher_id,
            data: &ciphertext1.ciphertext[32 * 15..],
        },
        &mut buf2,
    )?;
    response.push(Advance::SymmDecryptFinal as u8).ok();
    se050.run_command(&DeleteCryptoObj { id: cipher_id }, &mut buf2)?;
    response.push(Advance::SymmDecryptDelete as u8).ok();
    se050.run_command(&DeleteSecureObject { object_id: key_id }, &mut buf2)?;
    response.push(Advance::SymmDelete as u8).ok();
    Ok(())
}

#[cfg(feature = "se050")]
fn run_mac<Twi: I2CForT1, D: DelayUs<u32>, const N: usize>(
    se050: &mut Se050<Twi, D>,
    response: &mut Vec<u8, N>,
) -> Result<(), Status> {
    use se050::se050::{
        commands::{
            CreateSignatureObject, DeleteCryptoObj, MacGenerateFinal, MacGenerateInit,
            MacOneShotGenerate, MacOneShotValidate, MacUpdate, MacValidateFinal, MacValidateInit,
            WriteSymmKey,
        },
        CryptoObjectId, MacAlgo, SymmKeyType,
    };

    let mut buf = [0; 1000];
    let mut buf2 = [0; 1000];
    let plaintext_data = [2; 32 * 15];
    let key_id = ObjectId(hex!("03445566"));
    let mac_id = CryptoObjectId(hex!("0123"));
    let key = [0x42; 32];
    se050.run_command(
        &WriteSymmKey {
            transient: false,
            is_auth: false,
            key_type: SymmKeyType::Hmac,
            policy: None,
            max_attempts: None,
            object_id: key_id,
            kek_id: None,
            value: &key,
        },
        &mut buf,
    )?;
    response.push(Advance::MacWrite as u8).ok();
    let tag1 = se050.run_command(
        &MacOneShotGenerate {
            key_id,
            data: &plaintext_data,
            algo: MacAlgo::HmacSha256,
        },
        &mut buf,
    )?;
    response.push(Advance::MacSignOneShot as u8).ok();
    let res = se050.run_command(
        &MacOneShotValidate {
            key_id,
            algo: MacAlgo::HmacSha256,
            data: &plaintext_data,
            tag: tag1.tag,
        },
        &mut buf2,
    )?;
    response.push(Advance::MacVerifyOneShot as u8).ok();
    if res.result != Se050Result::Success {
        return Err(0x6008.into());
    }
    se050.run_command(
        &CreateSignatureObject {
            id: mac_id,
            subtype: MacAlgo::HmacSha256,
        },
        &mut buf2,
    )?;
    response.push(Advance::MacSignCreate as u8).ok();
    se050.run_command(&MacGenerateInit { key_id, mac_id }, &mut buf2)?;
    response.push(Advance::MacSignInit as u8).ok();
    se050.run_command(
        &MacUpdate {
            mac_id,
            data: &plaintext_data[0..32 * 10],
        },
        &mut buf2,
    )?;
    response.push(Advance::MacSignUpdate1 as u8).ok();
    se050.run_command(
        &MacUpdate {
            mac_id,
            data: &plaintext_data[32 * 10..][..32 * 5],
        },
        &mut buf2,
    )?;
    response.push(Advance::MacSignUpdate2 as u8).ok();
    let tag2 = se050.run_command(
        &MacGenerateFinal {
            mac_id,
            data: &plaintext_data[32 * 15..],
        },
        &mut buf2,
    )?;
    response.push(Advance::MacSignFinal as u8).ok();
    assert_eq!(tag2.tag, tag1.tag);
    se050.run_command(&DeleteCryptoObj { id: mac_id }, &mut buf)?;
    response.push(Advance::MacSignDelete as u8).ok();

    se050.run_command(
        &CreateSignatureObject {
            id: mac_id,
            subtype: MacAlgo::HmacSha256,
        },
        &mut buf,
    )?;
    response.push(Advance::MacVerifyCreate as u8).ok();
    se050.run_command(&MacValidateInit { key_id, mac_id }, &mut buf)?;
    response.push(Advance::MacVerifyInit as u8).ok();
    se050.run_command(
        &MacUpdate {
            mac_id,
            data: &plaintext_data[0..32 * 10],
        },
        &mut buf,
    )?;
    response.push(Advance::MacVerifyUpdate1 as u8).ok();
    se050.run_command(
        &MacUpdate {
            mac_id,
            data: &plaintext_data[32 * 10..][..32 * 5],
        },
        &mut buf,
    )?;
    response.push(Advance::MacVerifyUpdate2 as u8).ok();
    let res2 = se050.run_command(
        &MacValidateFinal {
            mac_id,
            data: &plaintext_data[32 * 15..],
            tag: tag2.tag,
        },
        &mut buf,
    )?;
    if res2.result != Se050Result::Success {
        return Err(0x6009.into());
    }
    response.push(Advance::MacVerifyFinal as u8).ok();

    se050.run_command(&DeleteCryptoObj { id: mac_id }, &mut buf)?;
    response.push(Advance::MacVerifyDelete as u8).ok();

    se050.run_command(&DeleteSecureObject { object_id: key_id }, &mut buf2)?;
    response.push(Advance::MacDelete as u8).ok();
    Ok(())
}
