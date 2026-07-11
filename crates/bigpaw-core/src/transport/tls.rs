//! 证书 pinning 的 TLS 配置。信任模型:不走 CA 链——
//! 客户端 pin 目标 fingerprint(证书 SHA-256);服务端接受任意自签证书,
//! 握手后从对端证书哈希得到 fingerprint 作为身份(设计文档 §5.1)。

use crate::identity::Identity;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring, verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CommonState, DigitallySignedStruct, DistinguishedName, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("rustls: {0}")]
    Rustls(#[from] rustls::Error),
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring::default_provider())
}

fn fp_of(cert: &CertificateDer<'_>) -> String {
    hex::encode(Sha256::digest(cert.as_ref()))
}

/// 从已完成握手的连接取对端 fingerprint。
pub fn peer_fingerprint(conn: &CommonState) -> Option<String> {
    conn.peer_certificates().and_then(|c| c.first()).map(fp_of)
}

/// 客户端验证器:pin 精确 fingerprint。
#[derive(Debug)]
struct PinnedServerVerifier {
    expected_fp: String,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if fp_of(end_entity) == self.expected_fp {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// 服务端验证器:接受任意能完成签名证明的自签证书(身份=证书哈希,握手后读取)。
#[derive(Debug)]
struct AnySelfSignedClientVerifier {
    provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for AnySelfSignedClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn cert_key(identity: &Identity) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = CertificateDer::from(identity.cert_der.clone());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.key_der.clone()));
    (vec![cert], key)
}

pub fn server_config(identity: &Identity) -> Result<Arc<rustls::ServerConfig>, TlsError> {
    let p = provider();
    let (certs, key) = cert_key(identity);
    let cfg = rustls::ServerConfig::builder_with_provider(p.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(AnySelfSignedClientVerifier { provider: p }))
        .with_single_cert(certs, key)?;
    Ok(Arc::new(cfg))
}

pub fn client_config(
    identity: &Identity,
    expected_fp: &str,
) -> Result<Arc<rustls::ClientConfig>, TlsError> {
    let p = provider();
    let (certs, key) = cert_key(identity);
    let cfg = rustls::ClientConfig::builder_with_provider(p.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServerVerifier {
            expected_fp: expected_fp.to_string(),
            provider: p,
        }))
        .with_client_auth_cert(certs, key)?;
    Ok(Arc::new(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    /// localhost 真实握手:server 识别 client fp,client pin server fp
    #[test]
    fn handshake_identifies_both_fingerprints() {
        let da = tempfile::tempdir().unwrap();
        let db = tempfile::tempdir().unwrap();
        let ida = Identity::load_or_create(da.path()).unwrap(); // server
        let idb = Identity::load_or_create(db.path()).unwrap(); // client
        let fa = ida.fingerprint.clone();
        let fb = idb.fingerprint.clone();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let sc = server_config(&ida).unwrap();

        let server = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let conn = rustls::ServerConnection::new(sc).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, tcp);
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).unwrap(); // 驱动握手完成
            assert_eq!(&buf, b"ping");
            peer_fingerprint(&tls.conn).expect("server 应能识别 client fp")
        });

        let cc = client_config(&idb, &fa).unwrap();
        let name = rustls::pki_types::ServerName::try_from("bigpaw").unwrap();
        let conn = rustls::ClientConnection::new(cc, name).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, TcpStream::connect(addr).unwrap());
        tls.write_all(b"ping").unwrap();
        tls.flush().unwrap();
        let seen_client_fp = server.join().unwrap();
        assert_eq!(seen_client_fp, fb);
        assert_eq!(peer_fingerprint(&tls.conn).unwrap(), fa);
    }

    /// pin 不匹配必须握手失败
    #[test]
    fn wrong_pin_is_rejected() {
        let da = tempfile::tempdir().unwrap();
        let db = tempfile::tempdir().unwrap();
        let ida = Identity::load_or_create(da.path()).unwrap();
        let idb = Identity::load_or_create(db.path()).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let sc = server_config(&ida).unwrap();
        std::thread::spawn(move || {
            if let Ok((tcp, _)) = listener.accept() {
                let conn = rustls::ServerConnection::new(sc).unwrap();
                let mut tls = rustls::StreamOwned::new(conn, tcp);
                let mut buf = [0u8; 1];
                let _ = tls.read(&mut buf); // 握手失败时这里返回 Err
            }
        });

        let wrong_fp = "0".repeat(64);
        let cc = client_config(&idb, &wrong_fp).unwrap();
        let name = rustls::pki_types::ServerName::try_from("bigpaw").unwrap();
        let conn = rustls::ClientConnection::new(cc, name).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, TcpStream::connect(addr).unwrap());
        let err = tls.write_all(b"x").and_then(|_| tls.flush());
        assert!(err.is_err(), "pin 不匹配应导致握手/写入失败");
    }
}
