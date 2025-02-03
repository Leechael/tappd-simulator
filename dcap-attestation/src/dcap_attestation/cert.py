from datetime import datetime, timezone
from typing import Optional, List, Dict
import re

from pydantic import BaseModel, Field
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ObjectIdentifier
from pyasn1.codec.der import decoder
from pyasn1.type import namedtype, univ

# https://github.com/mattlockyer/dcap-qvl/blob/139eafd40e9454cda2777831f37ac2cb514308e4/src/constants.rs
class SgxExtensionOids:
    """ Collection of OIDs used in DCAP attestation
    """
    SGX_EXTENSION = ObjectIdentifier("1.2.840.113741.1.13.1")
    PPID = univ.ObjectIdentifier("1.2.840.113741.1.13.1.1")
    TCB = univ.ObjectIdentifier("1.2.840.113741.1.13.1.2")
    PCEID = univ.ObjectIdentifier("1.2.840.113741.1.13.1.3")
    FMSPC = univ.ObjectIdentifier("1.2.840.113741.1.13.1.4")
    SGX_TYPE = univ.ObjectIdentifier("1.2.840.113741.1.13.1.5")
    PLATFORM_INSTANCE_ID = univ.ObjectIdentifier("1.2.840.113741.1.13.1.6")
    CONFIGURATION = univ.ObjectIdentifier("1.2.840.113741.1.13.1.7")
    PCESVN = univ.ObjectIdentifier("1.2.840.113741.1.13.1.2.17")
    CPUSVN = univ.ObjectIdentifier("1.2.840.113741.1.13.1.2.18")

class SgxExtensionValue(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('oid', univ.ObjectIdentifier()),
        namedtype.NamedType('value', univ.Any())
    )

class SgxExtensionSequence(univ.SequenceOf):
    componentType = SgxExtensionValue()


# check https://github.com/Phala-Network/dstack/blob/master/ra-tls/src/oids.rs
OID_PHALA_RATLS_QUOTE = ObjectIdentifier("1.3.6.1.4.1.62397.1.1")
OID_PHALA_RATLS_EVENT_LOG = ObjectIdentifier("1.3.6.1.4.1.62397.1.2")
OID_PHALA_RATLS_APP_INFO = ObjectIdentifier("1.3.6.1.4.1.62397.1.3")


class SgxExtension(BaseModel):
    ppid: Optional[str] = Field(None, description="PPID") 
    tcb: Optional[str] = Field(None, description="TCB")
    pceid: Optional[str] = Field(None, description="PCEID")
    fmspc: Optional[str] = Field(None, description="FMSPC")
    sgx_type: Optional[str] = Field(None, description="SGX Type")
    platform_instance_id: Optional[str] = Field(None, description="Platform Instance ID")
    configuration: Optional[str] = Field(None, description="Configuration")
    pcesvn: Optional[str] = Field(None, description="PCE SVN")
    cpusvn: Optional[str] = Field(None, description="CPU SVN")


class CertificateSubject(BaseModel):
    common_name: Optional[str] = Field(None, description="Certificate subject common name")
    organization: Optional[str] = Field(None, description="Organization name")
    country: Optional[str] = Field(None, description="Country code")
    state: Optional[str] = Field(None, description="State or province")
    locality: Optional[str] = Field(None, description="Locality name")


class CertificateIssuer(BaseModel):
    common_name: Optional[str] = Field(None, description="Issuer common name")
    organization: Optional[str] = Field(None, description="Issuer organization")
    country: Optional[str] = Field(None, description="Issuer country code")


class Certificate(BaseModel):
    subject: CertificateSubject
    issuer: CertificateIssuer
    serial_number: str
    not_before: datetime
    not_after: datetime
    version: str
    fingerprint: str
    signature_algorithm: str
    sans: Optional[List[str]] = None
    is_ca: bool = False
    position_in_chain: Optional[int] = None
    quote: Optional[str] = None
    sgx_extensions: Optional[SgxExtension] = None
    raw: Optional[str] = Field(None, exclude=True)

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class CertificateChainValidation(BaseModel):
    valid: bool
    messages: List[str]


def get_name_value(name: x509.Name, oid: x509.ObjectIdentifier) -> Optional[str]:
    """Extract specific OID value from certificate name"""
    try:
        return name.get_attributes_for_oid(oid)[0].value
    except:
        return None


def parse_certificate_from_pem(cert_pem: str) -> Certificate:
    """Parse a single PEM-formatted X.509 certificate into a Certificate model"""
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode("ascii"), default_backend())

        subject = cert.subject
        subject_dict = CertificateSubject(
            common_name=get_name_value(subject, NameOID.COMMON_NAME),
            organization=get_name_value(subject, NameOID.ORGANIZATION_NAME),
            country=get_name_value(subject, NameOID.COUNTRY_NAME),
            state=get_name_value(subject, NameOID.STATE_OR_PROVINCE_NAME),
            locality=get_name_value(subject, NameOID.LOCALITY_NAME),
        )

        issuer = cert.issuer
        issuer_dict = CertificateIssuer(
            common_name=get_name_value(issuer, NameOID.COMMON_NAME),
            organization=get_name_value(issuer, NameOID.ORGANIZATION_NAME),
            country=get_name_value(issuer, NameOID.COUNTRY_NAME),
        )

        # Extract SANs if present
        try:
            sans = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            sans_list = [str(san) for san in sans.value]
        except x509.ExtensionNotFound:
            sans_list = None

        # Check if cert is CA
        try:
            basic_constraints = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.BASIC_CONSTRAINTS
            )
            is_ca = basic_constraints.value.ca
        except x509.ExtensionNotFound:
            is_ca = False

        # TODO(lee): not yet tested, migrate from asn1 to pyasn1
        quote = None
        try:
            ext = cert.extensions.get_extension_for_oid(OID_PHALA_RATLS_QUOTE)
            decoded, _ = decoder.decode(ext.value.value)
            quote = bytes(decoded).hex()
        except:
            pass

        sgx_extensions = None
        try:
            rs = cert.extensions.get_extension_for_oid(SgxExtensionOids.SGX_EXTENSION)
            decoded, _ = decoder.decode(rs.value.value, asn1Spec=SgxExtensionSequence())
            sgx_extensions = SgxExtension()
            for item in decoded:
                if item['oid'] == SgxExtensionOids.FMSPC:
                    value_bytes = bytes(item['value'])[2:]
                    sgx_extensions.fmspc = value_bytes.hex()
                elif item['oid'] == SgxExtensionOids.PPID:
                    value_bytes = bytes(item['value'])[2:]
                    sgx_extensions.ppid = value_bytes.hex()
                elif item['oid'] == SgxExtensionOids.TCB:
                    value_bytes = bytes(item['value'])[2:]
                    sgx_extensions.tcb = value_bytes.hex()
                elif item['oid'] == SgxExtensionOids.PCEID:
                    value_bytes = bytes(item['value'])[2:]
                    sgx_extensions.pceid = value_bytes.hex()
                elif item['oid'] == SgxExtensionOids.SGX_TYPE:
                    value_bytes = bytes(item['value'])[2:]
                    sgx_extensions.sgx_type = value_bytes.hex()
                elif item['oid'] == SgxExtensionOids.PLATFORM_INSTANCE_ID:
                    value_bytes = bytes(item['value'])[2:]
                    sgx_extensions.platform_instance_id = value_bytes.hex()
                elif item['oid'] == SgxExtensionOids.CONFIGURATION:
                    value_bytes = bytes(item['value'])[2:]
                    sgx_extensions.configuration = value_bytes.hex()
                elif item['oid'] == SgxExtensionOids.PCESVN:
                    value_bytes = bytes(item['value'])[2:]
                    sgx_extensions.pcesvn = value_bytes.hex()
                elif item['oid'] == SgxExtensionOids.CPUSVN:
                    value_bytes = bytes(item['value'])[2:]
                    sgx_extensions.cpusvn = value_bytes.hex()
        except:
            pass

        return Certificate(
            subject=subject_dict,
            issuer=issuer_dict,
            serial_number=format(cert.serial_number, "x"),
            not_before=cert.not_valid_before_utc,
            not_after=cert.not_valid_after_utc,
            version=cert.version.name,
            fingerprint=cert.fingerprint(cert.signature_hash_algorithm).hex(),
            signature_algorithm=cert.signature_algorithm_oid._name,
            sans=sans_list,
            is_ca=is_ca,
            quote=quote,
            sgx_extensions=sgx_extensions,
            raw=cert_pem,
        )
    except Exception as e:
        raise ValueError(f"Failed to parse certificate: {str(e)}")


def split_pem_chain(pem_data: str) -> List[str]:
    """Split a PEM file containing multiple certificates into individual certificates"""
    pattern = r"-----BEGIN CERTIFICATE-----\r?\n.+?\r?\n-----END CERTIFICATE-----\r?\n?"
    return re.findall(pattern, pem_data, re.DOTALL)


def parse_certificate_chain(pem_data: str) -> List[Certificate]:
    """Parse a PEM-formatted certificate chain into a list of Certificate models"""
    cert_chain = split_pem_chain(pem_data)
    parsed_chain = []
    for i, cert_pem in enumerate(cert_chain):
        cert = parse_certificate_from_pem(cert_pem)
        cert.position_in_chain = i
        parsed_chain.append(cert)
    return parsed_chain


def verify_certificate_chain(cert_chain: List[Certificate]) -> CertificateChainValidation:
    """Verify the validity of a certificate chain"""
    result = CertificateChainValidation(valid=True, messages=[])
    now = datetime.now(timezone.utc)

    for i in range(len(cert_chain) - 1):
        current_cert = cert_chain[i]
        issuer_cert = cert_chain[i + 1]

        if current_cert.issuer.common_name != issuer_cert.subject.common_name:
            result.valid = False
            result.messages.append(
                f"Certificate chain broken: Certificate {i}'s issuer doesn't match certificate {i+1}'s subject"
            )

        if now < current_cert.not_before or now > current_cert.not_after:
            result.valid = False
            result.messages.append(f"Certificate {i} is expired or not yet valid")

    return result
