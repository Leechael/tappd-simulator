#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/obj_mac.h>

#define QUOTE_SIZE 8192
#define HEADER_SIZE 48
#define REPORT_SIZE 384
#define ECDSA_SIG_SIZE 64
#define ECDSA_PUBKEY_SIZE 64
#define QE_REPORT_SIZE 384
#define QE_AUTH_DATA_SIZE 32
#define CERTIFICATION_DATA_SIZE 4096
#define FMSPC_SIZE 6

typedef struct {
    uint16_t version;
    uint16_t att_key_type;
    uint32_t tee_type;
    uint8_t reserved[4];
    uint16_t qe_svn;
    uint16_t pce_svn;
    uint8_t qe_vendor_id[16];
    uint8_t user_data[20];
} QuoteHeader;

typedef struct {
    uint8_t report_data[64];
    uint8_t other_data[320];
} Report;

typedef struct {
    uint32_t auth_data_size;
    uint8_t ecdsa_signature[ECDSA_SIG_SIZE];
    uint8_t ecdsa_attestation_key[ECDSA_PUBKEY_SIZE];
    uint8_t qe_report[QE_REPORT_SIZE];
    uint8_t qe_report_signature[ECDSA_SIG_SIZE];
    uint16_t qe_auth_data_size;
    uint8_t qe_auth_data[QE_AUTH_DATA_SIZE];
    uint16_t certification_data_type;
    uint32_t certification_data_size;
    uint8_t certification_data[CERTIFICATION_DATA_SIZE];
} AuthDataV3;

void generate_random_bytes(uint8_t *buffer, size_t length) {
    for (size_t i = 0; i < length; i++) {
        buffer[i] = rand() % 256;
    }
}

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void create_openssl_config(const uint8_t* fmspc, const char* cert_type) {
    FILE* config = fopen("openssl.cnf", "w");
    if (!config) {
        perror("Failed to create OpenSSL config file");
        exit(1);
    }

    fprintf(config, "[ req ]\n");
    fprintf(config, "distinguished_name = req_distinguished_name\n");
    fprintf(config, "x509_extensions = v3_ca\n");
    fprintf(config, "[ req_distinguished_name ]\n");
    fprintf(config, "[ v3_ca ]\n");
    fprintf(config, "subjectKeyIdentifier = hash\n");
    fprintf(config, "authorityKeyIdentifier = keyid:always,issuer\n");
    if (strcmp(cert_type, "leaf") == 0) {
        uint8_t cpu_svn[16];
        generate_random_bytes(cpu_svn, 16);

        uint16_t pce_svn;
        pce_svn = (uint16_t)(rand() % 65535 + 1);

        fprintf(config, "basicConstraints = critical, CA:FALSE\n");
        fprintf(config, "keyUsage = critical, digitalSignature\n");
        fprintf(config, "extendedKeyUsage = critical, serverAuth, clientAuth\n");
        fprintf(config, "1.2.840.113741.1.13.1 = ASN1:SEQUENCE:intel_sgx_ext\n");
        fprintf(config, "[ intel_sgx_ext ]\n");
        fprintf(config, "fmspc = SEQUENCE:fmspc_seq\n");
        fprintf(config, "tcb = SEQUENCE:tcb_seq\n");
        fprintf(config, "[ fmspc_seq ]\n");
        fprintf(config, "fmspc_oid = OID:1.2.840.113741.1.13.1.4\n");
        fprintf(config, "fmspc_value = FORMAT:HEX,OCTETSTRING:%02X%02X%02X%02X%02X%02X\n", 
                fmspc[0], fmspc[1], fmspc[2], fmspc[3], fmspc[4], fmspc[5]);
        fprintf(config, "[ tcb_seq ]\n");
        fprintf(config, "tcb_oid = OID:1.2.840.113741.1.13.1.2\n");
        fprintf(config, "tcb_value = SEQUENCE:tcb_components\n");
        fprintf(config, "[ tcb_components ]\n");
        fprintf(config, "cpusvn = SEQUENCE:cpusvn_seq\n");
        fprintf(config, "pcesvn = SEQUENCE:pcesvn_seq\n");
        fprintf(config, "[ cpusvn_seq ]\n");
        fprintf(config, "cpusvn_oid = OID:1.2.840.113741.1.13.1.2.18\n");
        fprintf(config, "cpusvn_value = FORMAT:HEX,OCTETSTRING:");
        for (int i = 0; i < 16; i++) {
            fprintf(config, "%02X", cpu_svn[i]);
        }
        fprintf(config, "\n");
        fprintf(config, "[ pcesvn_seq ]\n");
        fprintf(config, "pcesvn_oid = OID:1.2.840.113741.1.13.1.2.17\n");
        fprintf(config, "pcesvn_value = INTEGER:%d\n", pce_svn);
    } else {
        fprintf(config, "basicConstraints = critical, CA:TRUE\n");
        fprintf(config, "keyUsage = critical, digitalSignature, cRLSign, keyCertSign\n");
    }

    fclose(config);
}

int generate_cert_chain(char* cert_chain, size_t cert_chain_size, const uint8_t* fmspc) {
    create_openssl_config(fmspc, "root");

    system("openssl ecparam -name prime256v1 -genkey -noout -out root.key");
    system("openssl req -new -x509 -key root.key -out root.crt -days 3650 -nodes -subj '/CN=Intel SGX Root CA' -config openssl.cnf -extensions v3_ca");
    
    create_openssl_config(fmspc, "intermediate");

    system("openssl ecparam -name prime256v1 -genkey -noout -out intermediate.key");
    system("openssl req -new -key intermediate.key -out intermediate.csr -subj '/CN=Intel SGX PCK Platform CA'");
    system("openssl x509 -req -in intermediate.csr -CA root.crt -CAkey root.key -CAcreateserial -out intermediate.crt -days 1825 -extfile openssl.cnf -extensions v3_ca");

    create_openssl_config(fmspc, "leaf");

    system("openssl ecparam -name prime256v1 -genkey -noout -out leaf.key");
    system("openssl req -new -key leaf.key -out leaf.csr -subj '/CN=Intel SGX PCK Certificate'");
    system("openssl x509 -req -in leaf.csr -CA intermediate.crt -CAkey intermediate.key -CAcreateserial -out leaf.crt -days 365 -extfile openssl.cnf -extensions v3_ca");

    FILE *leaf_cert = fopen("leaf.crt", "r");
    FILE *intermediate_cert = fopen("intermediate.crt", "r");
    FILE *root_cert = fopen("root.crt", "r");
    
    if (!leaf_cert || !intermediate_cert || !root_cert) {
        perror("Failed to open certificate files");
        return -1;
    }

    size_t bytes_written = 0;
    char buffer[1024];
    
    while (fgets(buffer, sizeof(buffer), leaf_cert) && bytes_written < cert_chain_size) {
        bytes_written += snprintf(cert_chain + bytes_written, cert_chain_size - bytes_written, "%s", buffer);
    }
    
    while (fgets(buffer, sizeof(buffer), intermediate_cert) && bytes_written < cert_chain_size) {
        bytes_written += snprintf(cert_chain + bytes_written, cert_chain_size - bytes_written, "%s", buffer);
    }

    while (fgets(buffer, sizeof(buffer), root_cert) && bytes_written < cert_chain_size) {
        bytes_written += snprintf(cert_chain + bytes_written, cert_chain_size - bytes_written, "%s", buffer);
    }

    fclose(leaf_cert);
    fclose(intermediate_cert);
    fclose(root_cert);

    printf("Generated certificate chain length: %zu\n", bytes_written);

    return 0;
}

void print_openssl_errors() {
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char *str = ERR_error_string(err, 0);
        if (str) {
            fprintf(stderr, "%s\n", str);
        }
    }
}

void get_public_key(uint8_t *pub_key) {
    FILE *f = fopen("leaf.key", "r");
    if (!f) {
        perror("Failed to open leaf.key");
        exit(1);
    }
    
    EC_KEY *eckey = PEM_read_ECPrivateKey(f, NULL, NULL, NULL);
    fclose(f);

    if (!eckey) {
        fprintf(stderr, "Failed to read private key\n");
        print_openssl_errors();
        exit(1);
    }

    const EC_POINT *pub_key_point = EC_KEY_get0_public_key(eckey);
    const EC_GROUP *group = EC_KEY_get0_group(eckey);

    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();

    if (!EC_POINT_get_affine_coordinates(group, pub_key_point, x, y, NULL)) {
        fprintf(stderr, "Failed to get public key coordinates\n");
        print_openssl_errors();
        EC_KEY_free(eckey);
        BN_free(x);
        BN_free(y);
        exit(1);
    }

    BN_bn2binpad(x, pub_key, 32);
    BN_bn2binpad(y, pub_key + 32, 32);

    EC_KEY_free(eckey);
    BN_free(x);
    BN_free(y);
}

void sign_data(const uint8_t *data, size_t data_len, uint8_t *signature) {
    EC_KEY *eckey = NULL;
    FILE *f = fopen("leaf.key", "r");
    if (!f) {
        perror("Failed to open leaf.key");
        exit(1);
    }
    
    eckey = PEM_read_ECPrivateKey(f, NULL, NULL, NULL);
    fclose(f);

    if (!eckey) {
        fprintf(stderr, "Failed to read private key\n");
        print_openssl_errors();
        exit(1);
    }

    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(data, data_len, hash);

    ECDSA_SIG *sig = ECDSA_do_sign(hash, SHA256_DIGEST_LENGTH, eckey);
    if (sig == NULL) {
        fprintf(stderr, "Failed to generate ECDSA signature\n");
        print_openssl_errors();
        EC_KEY_free(eckey);
        exit(1);
    }

    const BIGNUM *r, *s;
    ECDSA_SIG_get0(sig, &r, &s);

    if (BN_bn2binpad(r, signature, 32) != 32 || BN_bn2binpad(s, signature + 32, 32) != 32) {
        fprintf(stderr, "Failed to convert signature to binary\n");
        print_openssl_errors();
        ECDSA_SIG_free(sig);
        EC_KEY_free(eckey);
        exit(1);
    }

    printf("Generated signature:\n");
    print_hex("Signature", signature, ECDSA_SIG_SIZE);

    ECDSA_SIG_free(sig);
    EC_KEY_free(eckey);
}

void calculate_qe_report_hash(const uint8_t *ecdsa_attestation_key, const uint8_t *qe_auth_data, uint8_t *hash) {
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(md_ctx, ecdsa_attestation_key, ECDSA_PUBKEY_SIZE);
    EVP_DigestUpdate(md_ctx, qe_auth_data, QE_AUTH_DATA_SIZE);
    unsigned int md_len;
    EVP_DigestFinal_ex(md_ctx, hash, &md_len);
    EVP_MD_CTX_free(md_ctx);
    
    printf("Generated QE report hash:\n");
    print_hex("QE Report Hash", hash, md_len);
}

int main() {
    srand(time(NULL));
    
    uint8_t quote[QUOTE_SIZE] = {0};
    QuoteHeader *header = (QuoteHeader *)quote;
    Report *report = (Report *)(quote + HEADER_SIZE);
    AuthDataV3 *auth_data = (AuthDataV3 *)(quote + HEADER_SIZE + REPORT_SIZE);
    
    // Set header fields
    header->version = 3;
    header->att_key_type = 2;  // ECDSA_P256
    header->tee_type = 0;  // SGX
    header->qe_svn = 1;
    header->pce_svn = 1;
    generate_random_bytes(header->qe_vendor_id, sizeof(header->qe_vendor_id));
    generate_random_bytes(header->user_data, sizeof(header->user_data));
    
    // Set report data
    generate_random_bytes((uint8_t*)report, sizeof(Report));
    
    // Generate certificate chain
    char cert_chain[CERTIFICATION_DATA_SIZE] = {0};
    uint8_t fmspc[FMSPC_SIZE] = {0x00, 0x90, 0x6E, 0xA1, 0x00, 0x00};
    
    if (generate_cert_chain(cert_chain, CERTIFICATION_DATA_SIZE, fmspc) != 0) {
        fprintf(stderr, "Failed to generate certificate chain\n");
        return 1;
    }
    
    // Verify private key after generating certificate chain
    FILE *f = fopen("leaf.key", "r");
    if (!f) {
        perror("Failed to open leaf.key");
        return 1;
    }
    EC_KEY *eckey = PEM_read_ECPrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!eckey) {
        fprintf(stderr, "Failed to read private key\n");
        print_openssl_errors();
        return 1;
    }
    EC_KEY_free(eckey);

    // Set auth data fields
    auth_data->auth_data_size = sizeof(AuthDataV3) - sizeof(uint32_t);
    get_public_key(auth_data->ecdsa_attestation_key);
    auth_data->qe_auth_data_size = QE_AUTH_DATA_SIZE;
    generate_random_bytes(auth_data->qe_auth_data, QE_AUTH_DATA_SIZE);
    auth_data->certification_data_type = 5;  // PCK_CERT_CHAIN
    auth_data->certification_data_size = strlen(cert_chain);
    memcpy(auth_data->certification_data, cert_chain, auth_data->certification_data_size);
    
    // Generate and set QE Report
    memset(auth_data->qe_report, 0, QE_REPORT_SIZE);
    uint8_t qe_report_hash[32];
    calculate_qe_report_hash(auth_data->ecdsa_attestation_key, auth_data->qe_auth_data, qe_report_hash);
    memcpy(auth_data->qe_report + QE_REPORT_SIZE - 64, qe_report_hash, 32);

    printf("Data to be signed (Quote):\n");
    print_hex("Quote data", quote, HEADER_SIZE + REPORT_SIZE);
    
    // Sign the quote
    size_t signed_quote_len = HEADER_SIZE + REPORT_SIZE;
    sign_data(quote, signed_quote_len, auth_data->ecdsa_signature);

    // Verify the quote signature
    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT *pub_point = EC_POINT_new(EC_KEY_get0_group(eckey));
    EC_POINT_oct2point(EC_KEY_get0_group(eckey), pub_point, auth_data->ecdsa_attestation_key, ECDSA_PUBKEY_SIZE, NULL);
    EC_KEY_set_public_key(eckey, pub_point);

    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(quote, signed_quote_len, hash);

    ECDSA_SIG *sig = ECDSA_SIG_new();
    BIGNUM *r = BN_bin2bn(auth_data->ecdsa_signature, 32, NULL);
    BIGNUM *s = BN_bin2bn(auth_data->ecdsa_signature + 32, 32, NULL);
    ECDSA_SIG_set0(sig, r, s);

    int verify_result = ECDSA_do_verify(hash, SHA256_DIGEST_LENGTH, sig, eckey);

    if (verify_result != 1) {
        fprintf(stderr, "Quote signature verification failed\n");
        print_openssl_errors();
    } else {
        printf("Quote signature verified successfully\n");
    }

    ECDSA_SIG_free(sig);
    EC_POINT_free(pub_point);
    EC_KEY_free(eckey);

    printf("QE Report to be signed:\n");
    print_hex("QE Report", auth_data->qe_report, QE_REPORT_SIZE);
    
    // Sign the QE report
    sign_data(auth_data->qe_report, QE_REPORT_SIZE, auth_data->qe_report_signature);

    // Verify the QE report signature
    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    pub_point = EC_POINT_new(EC_KEY_get0_group(eckey));
    EC_POINT_oct2point(EC_KEY_get0_group(eckey), pub_point, auth_data->ecdsa_attestation_key, ECDSA_PUBKEY_SIZE, NULL);
    EC_KEY_set_public_key(eckey, pub_point);

    SHA256(auth_data->qe_report, QE_REPORT_SIZE, hash);

    sig = ECDSA_SIG_new();
    r = BN_bin2bn(auth_data->qe_report_signature, 32, NULL);
    s = BN_bin2bn(auth_data->qe_report_signature + 32, 32, NULL);
    ECDSA_SIG_set0(sig, r, s);

    verify_result = ECDSA_do_verify(hash, SHA256_DIGEST_LENGTH, sig, eckey);

    if (verify_result != 1) {
        fprintf(stderr, "QE Report signature verification failed\n");
        print_openssl_errors();
    } else {
        printf("QE Report signature verified successfully\n");
    }

    ECDSA_SIG_free(sig);
    EC_POINT_free(pub_point);
    EC_KEY_free(eckey);
    
    // Write quote to file
    FILE *file = fopen("sgx_quote", "wb");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }
    
    size_t total_size = HEADER_SIZE + REPORT_SIZE + sizeof(AuthDataV3);
    size_t written = fwrite(quote, 1, total_size, file);
    fclose(file);
    
    printf("Wrote %zu bytes to sgx_quote\n", written);
    printf("FMSPC: %02X%02X%02X%02X%02X%02X\n", fmspc[0], fmspc[1], fmspc[2], fmspc[3], fmspc[4], fmspc[5]);

    printf("Content of sgx_quote:\n");
    char command[100];
    snprintf(command, sizeof(command), "xxd sgx_quote | head -n %d", (int)(total_size / 16 + 1));
    system(command);
    
    print_hex("QE Auth Data", auth_data->qe_auth_data, QE_AUTH_DATA_SIZE);
    printf("QE Auth Data Size: %u\n", auth_data->qe_auth_data_size);
    printf("Auth Data Size: %u\n", auth_data->auth_data_size);
    printf("Certification Data Size: %u\n", auth_data->certification_data_size);
    
    // Clean up
    remove("root.key");
    remove("root.crt");
    remove("intermediate.key");
    remove("intermediate.csr");
    remove("intermediate.crt");
    remove("leaf.key");
    remove("leaf.csr");
    remove("leaf.crt");
    remove("openssl.cnf");

    return 0;
}