# Fake TEE Quote generator

> [!IMPORTANT]
> This program cannot generate a legitimate report; it only produces fake quotes for testing and development purposes.

This is a toy program that generates fake TEE quotes compatible with [dcap-qvl](https://github.com/Phala-Network/dcap-qvl).

Currently, it only generates EnclaveReports. To use it, you must bypass the `unknownIssuer` issue described [here](https://github.com/Phala-Network/dcap-qvl/blob/master/src/utils.rs#L145-L167).

```rust
/// Verifies that the `leaf_cert` in combination with the `intermediate_certs` establishes
/// a valid certificate chain that is rooted in one of the trust anchors that was compiled into to the pallet
pub fn verify_certificate_chain(
    leaf_cert: &webpki::EndEntityCert,
    intermediate_certs: &[CertificateDer],
    verification_time: u64,
) -> Result<(), Error> {
    let time = webpki::types::UnixTime::since_unix_epoch(core::time::Duration::from_secs(
        verification_time / 1000,
    ));
    let sig_algs = &[webpki::ring::ECDSA_P256_SHA256];
    let result = leaf_cert
        .verify_for_usage(
            sig_algs,
            DCAP_SERVER_ROOTS,
            intermediate_certs,
            time,
            webpki::KeyUsage::server_auth(),
            None,
            None,
        );
    match result {
        Ok(_) => Ok(()),
        Err(e) => {
            println!("Certificate chain validation error: {:?}", e);
            match e {
                webpki::Error::UnknownIssuer => {
                    println!("Issuer not found for the certificate.");
                    Ok(())
                }
                _ => return Err(Error::CertificateChainIsInvalid)
            }
        }
    }
}
```
