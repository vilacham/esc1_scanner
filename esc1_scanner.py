# Standard library imports
import argparse
import getpass
import socket
import struct
import time

# Third-party imports
from colored import fore
from impacket.dcerpc.v5 import rrp, transport
from impacket.dcerpc.v5.dcom.oaut import DISPPARAMS, IDispatch
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.uuid import string_to_bin
from ldap3 import ALL, Connection, NTLM, Server
from ldap3.protocol.microsoft import security_descriptor_control


# Constants and Dicts
TAB = "  "


IID_ICERTADMIND2 = string_to_bin("7fe0d935-dda6-443f-85d0-1cfb58fe41dd")


CLSID_ICERTADMIND = string_to_bin("d99e6e73-fc88-11d0-b498-00a0c90312f3")


ALL_SID = dict()


COLORS = {
    "white": fore("white"),
    "blue": fore("blue"),
    "cyan": fore("cyan"),
    "green": fore("green_4"),
    "orange": fore("orange_3"),
    "red": fore("red")
}


CA_PERMISSIONS_ACCESS_MASKS = {
    0x00000001: [
        "Administrator",
        "Has full control of the CA (configuration, user accounts management, "
        "system maintenance)",
    ],
    0x00000002: [
        "Officer",
        "Authorized to approve or deny certificate requests and manage revocations",
    ],
    0x00000004: [
        "Auditor",
        "Authorized to view and maintain audit logs",
    ],
    0x00000008: [
        "Operator",
        "Authorized to perform system backup and recovery operations for the CA",
    ],
    0x00000100: [
        "Read",
        "Authorized to view basic CA properties (configuration and available templates)",
    ],
    0x00000200: [
        "Enroll",
        "Authorized to request certificates from the CA",
    ],
}


AD_OBJECTS_ACCESS_MASKS = {
    0x00000001: [
        "CC",
        "DS_CREATE_CHILD",
        "The right to create child objects of the object",
    ],
    0x00000002: [
        "DC",
        "DS_DELETE_CHILD",
        "The right to delete child objects of the object",
    ],
    0x00000004: [
        "LC",
        "DS_LIST_CONTENTS",
        "The right to list child objects of this object",
    ],
    # 0x00000008: ["SW", "SELF_WRITE", ""],
    0x00000008: [
        "VW",
        "DS_WRITE_PROPERTY_EXTENDED",
        "The right to perform an operation controlled by a validated write access right",
    ],
    0x00000010: [
        "RP",
        "DS_READ_PROPERTY",
        "The right to read properties of the object",
    ],
    0x00000020: [
        "WP",
        "DS_WRITE_PROPERTY",
        "The right to write properties of the object",
    ],
    0x00000040: [
        "DT",
        "DS_DELETE_TREE",
        "The right to perform a Delete-Tree operation on this object",
    ],
    0x00000080: [
        "LO",
        "DS_LIST_OBJECT",
        "The right to list a particular object",
    ],
    # 0x00000100: ["CR", "EXTENDED_RIGHT", ""],
    0x00000100: [
        "CR",
        "DS_CONTROL_ACCESS",
        "The right to perform an operation controlled by a control access right",
    ],
    0x00010000: ["DE", "DELETE", "The right to delete the object"],
    0x00020000: [
        "RC",
        "READ_CONTROL",
        "The right to read data from the security descriptor of the object, "
        "not including the data in the SACL",
    ],
    0x00040000: [
        "WD",
        "WRITE_DAC",
        "The right to modify the DACL in the object security descriptor",
    ],
    0x00080000: [
        "WO",
        "WRITE_OWNER",
        "The right to modify the owner of an object in the object's security descriptor",
    ],
}


ACL_REVISIONS = {
    2: ["Default", "Supports basic ACE types"],
    3: ["Compound", "Supports basic and coumpound ACE types"],
    4: ["Object", "Supports basic, compound and object ACE types"]
}


ACE_TYPES = {
    0x00: ["DACL", 2, "ACCESS_ALLOWED_ACE", "Grants access to a resource"],
    0x01: ["DACL", 2, "ACCESS_DENIED_ACE", "Denies access to a resource"],
    0x02: ["SACL", 2, "SYSTEM_AUDIT_ACE", "Audits access to a resource"],
    0x03: [
        "SACL",
        2,
        "SYSTEM_ALARM_ACE",
        "Alarms upon acess to a resource; unused",
    ],
    0x04: [
        "DACL",
        3,
        "ACCESS_ALLOWED_COMPOUND_ACE",
        "Grants access to a resource during impersonation",
    ],
    0x05: [
        "DACL",
        4,
        "ACCESS_ALLOWED_OBJECT_ACE",
        "Grants access to a resource with an object type",
    ],
    0x06: [
        "DACL",
        4,
        "ACCESS_DENIED_OBJECT_ACE",
        "Denies access to a resource with an object type",
    ],
    0x07: [
        "SACL",
        4,
        "SYSTEM_AUDIT_OBJECT_ACE",
        "Audits access to a resource with an object type",
    ],
    0x08: [
        "SACL",
        4,
        "SYSTEM_ALARM_OBJECT_ACE",
        "Alarms upon access to a resource with an object type; unused",
    ],
    0x09: [
        "DACL",
        2,
        "ACCESS_ALLOWED_CALLBACK_ACE",
        "Grants access to a resource with a callback",
    ],
    0x0A: [
        "DACL",
        2,
        "ACCESS_DENIED_CALLBACK_ACE",
        "Denies access to a resource with a callback",
    ],
    0x0B: [
        "DACL",
        4,
        "ACCESS_ALLOWED_CALLBACK_OBJECT_ACE",
        "Grants access to a resource with a callback and an object type",
    ],
    0x0C: [
        "DACL",
        4,
        "ACCESS_DENIED_CALLBACK_OBJECT_ACE",
        "Denies access to a resource with a callback and an object type",
    ],
    0x0D: [
        "SACL",
        2,
        "SYSTEM_AUDIT_CALLBACK_ACE",
        "Audits access to a resource with a callbackk",
    ],
    0x0E: [
        "SACL",
        2,
        "SYSTEM_ALARM_CALLBACK_ACE",
        "Alarms upon access to a resource with a callback; unused",
    ],
    0x0F: [
        "SACL",
        4,
        "SYSTEM_AUDIT_CALLBACK_OBJECT_ACE",
        "Audits access to a resource with a callback and an object type",
    ],
    0x10: [
        "SACL",
        4,
        "SYSTEM_ALARM_CALLBACK_OBJECT_ACE",
        "Alarms upon access to a resource with a callback and an object type; unused",
    ],
    0x11: ["SACL", 2, "SYSTEM_MANDATORY_LABEL_ACE", "Specifies a mandatory label"],
    0x12: [
        "SACL",
        2,
        "SYSTEM_RESOURCE_ATTRIBUTE_ACE",
        "Specifies attributes for the resource",
    ],
    0x13: [
        "SACL",
        2,
        "SYSTEM_SCOPED_POLICY_ID_ACE",
        "Specifie a central access policy ID for the resource",
    ],
    0x14: [
        "SACL",
        2,
        "SYSTEM_PROCESS_TRUST_LABEL_ACE",
        "Specifies a process trust label to limite resource access",
    ],
    0x15: [
        "SACL",
        2,
        "SYSTEM_ACCESS_FILTER_ACE",
        "Specifies an access filter for the resource",
    ],
}


ACE_FLAGS = {
    0x01: ["ObjectInherit", "The ACE can be inherited by an object"],
    0x02: ["ContainerInherit", "The ACE can be inherited by a container"],
    0x04: ["NoPropagateInherit", "The ACE's inheritance flags are not propagated to children"],
    0x08: ["InheritOnly", "The ACE is used only for inheritance and not for access checks"],
    0x10: ["Inherited", "The ACE was inherited from a parent container"],
    0x20: ["Critical", "The ACE is critical and can't be removed (applies only to Allowed ACEs)"],
    0x40: ["SuccessfulAccess", "An audit event should be generated for a successful access"],
    # 0x40: ["TrustProtected", "When used with an AccessFilter ACE, this flag prevents modification"]
    0x80: ["FailedAccess", "An audit event should be generated for a failed access"]
}


ENROLLMENT_FLAGS = {
    0x00000001: [
        "INCLUDE_SYMMETRIC_ALGORITHMS",
        "Include a Secure/Multipurpose Internet Mail Extensions (S/MIME) certificate extension "
        "in the request and the issued certificate",
    ],
    0x00000002: ["PEND_ALL_REQUESTS", "Put all requests in a pending state for manual approval"],
    0x00000004: [
        "PUBLISH_TO_KRA_CONTAINER",
        "Publish the issued certificate to the Key Recovery Agent (KRA) container in Active Directory",
    ],
    0x00000008: [
        "PUBLISH_TO_DS",
        "Append the issued certificate to the userCertificate attribute on the user object in Active Directory",
    ],
    0x00000010: [
        "AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE",
        "Prevent autoenrollment if a valid certificate based on the same template exists in the user's "
        "userCertificate attribute in Active Directory",
    ],
    0x00000020: ["AUTO_ENROLLMENT", "Allow clients to perform autoenrollment for the specified template"],
    0x00000040: [
        "PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT",
        "Require signing of renewal requests using the private key of the existing certificate",
    ],
    0x00000100: ["USER_INTERACTION_REQUIRED", "Require user consent before enrolling for a certificate"],
    0x00000400: [
        "REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE",
        "Delete invalid certificates based on the template from local certificate storage",
    ],
    0x00000800: ["ALLOW_ENROLL_ON_BEHALF_OF", "Enable enroll-on-behalf-of (EOBO) functionality"],
    0x00001000: [
        "ADD_OCSP_NOCHECK",
        "Do not include revocation information and add the id-pkix-ocsp-nocheck extension to the certificate",
    ],
    0x00002000: [
        "ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL",
        "Allow private key reuse for smart card-based certificate renewal if the card's keyset storage is full",
    ],
    0x00004000: ["NOREVOCATIONINFOINISSUEDCERTS", "Exclude revocation information from the issued certificate"],
    0x00008000: [
        "INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS",
        "Include the Basic Constraints extension in end entity certificates",
    ],
    0x00010000: [
        "ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT",
        "Ignore Enroll permissions on the template when processing renewal requests",
    ],
    0x00020000: [
        "ISSUANCE_POLICIES_FROM_REQUEST",
        "Include issuance policies from the request in the issued certificate, provided they match allowed "
        "policies in the template",
    ],
    0x00040000: ["SKIP_AUTO_RENEWAL", "Prevent auto-renewal of the certificate, even if it has a valid template"],
    0x00080000: [
        "NO_SECURITY_EXTENSION",
        "Exclude the szOID_NTDS_CA_SECURITY_EXT security extension from the issued certificate",
    ],
}


CERTIFICATE_NAME_FLAGS = {
    0x00000001: ["ENROLLEE_SUPPLIES_SUBJECT", "The subject name must be supplied by the enrollee"],
    0x00000008: [
        "OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME",
        "Reuse values of subject and alternative names from an existing valid certificate during renewal",
    ],
    0x00010000: [
        "ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME",
        "The subject alternate name must be supplied by the enrollee",
    ],
    0x00400000: [
        "SUBJECT_ALT_REQUIRE_DOMAIN_DNS",
        "Add the requestor's FQDN and NetBIOS name to the Subject Alternative Name extension",
    ],
    0x00800000: [
        "SUBJECT_ALT_REQUIRE_SPN",
        "Add the requestor's SPN attribute to the Subject Alternative Name extension",
    ],
    0x01000000: [
        "SUBJECT_ALT_REQUIRE_DIRECTORY_GUID",
        "Add the requestor's objectGUID attribute to the Subject Alternative Name extension",
    ],
    0x02000000: [
        "SUBJECT_ALT_REQUIRE_UPN",
        "Add the requestor's UPN attribute to the Subject Alternative Name extension",
    ],
    0x04000000: [
        "SUBJECT_ALT_REQUIRE_EMAIL",
        "Add the requestor's email attribute to the Subject Alternative Name extension",
    ],
    0x08000000: [
        "SUBJECT_ALT_REQUIRE_DNS",
        "Add the requestor's DNS attribute to the Subject Alternative Name extension",
    ],
    0x10000000: [
        "SUBJECT_REQUIRE_DNS_AS_CN",
        "Set the requestor's DNS attribute as the CN in the subject of the issued certificate",
    ],
    0x20000000: [
        "SUBJECT_REQUIRE_EMAIL",
        "Set the requestor's email attribute as the subject of the issued certificate",
    ],
    0x40000000: [
        "SUBJECT_REQUIRE_COMMON_NAME",
        "Set the subject name to the requestor's CN from Active Directory",
    ],
    0x80000000: [
        "SUBJECT_REQUIRE_DIRECTORY_PATH",
        "Set the subject name to the requestor's distinguished name (DN) from Active Directory",
    ],
}


EKUS = {
    "1.3.6.1.4.1.311.10.3.1": "Microsoft Trust List Signing",
    "1.3.6.1.4.1.311.10.3.10": "Qualified Subordination ",
    "1.3.6.1.4.1.311.10.3.11": "Key Recovery",
    "1.3.6.1.4.1.311.10.3.12": "Document Signing",
    "1.3.6.1.4.1.311.10.3.13": "Lifetime Signing",
    "1.3.6.1.4.1.311.10.3.19": "Revoked List Signer",
    "1.3.6.1.4.1.311.10.3.2": "Microsoft Time Stamping",
    "1.3.6.1.4.1.311.10.3.20": "Windows Kits Component",
    "1.3.6.1.4.1.311.10.3.21": "Windows RT Verification",
    "1.3.6.1.4.1.311.10.3.22": "Protected Process Light Verification",
    "1.3.6.1.4.1.311.10.3.23": "Windows TCB Component",
    "1.3.6.1.4.1.311.10.3.24": "Protected Process Verification",
    "1.3.6.1.4.1.311.10.3.25": "Windows Third Party Application Component",
    "1.3.6.1.4.1.311.10.3.26": "Windows Software Extension Verification",
    "1.3.6.1.4.1.311.10.3.27": "Preview Build Signing",
    "1.3.6.1.4.1.311.10.3.30": "Disallowed List",
    "1.3.6.1.4.1.311.10.3.39": "Windows Hardware Driver Extended Verification",
    "1.3.6.1.4.1.311.10.3.4": "Encrypting File System",
    "1.3.6.1.4.1.311.10.3.4.1": "File Recovery",
    "1.3.6.1.4.1.311.10.3.5": "Windows Hardware Driver Verification",
    "1.3.6.1.4.1.311.10.3.5.1": "Windows Hardware Driver Attested Verification",
    "1.3.6.1.4.1.311.10.3.6": "Windows System Component Verification ",
    "1.3.6.1.4.1.311.10.3.8": "Embedded Windows System Component Verification",
    "1.3.6.1.4.1.311.10.3.9": "Root List Signer",
    "1.3.6.1.4.1.311.10.5.1": "Digital Rights",
    "1.3.6.1.4.1.311.10.6.2": "License Server Verification",
    "1.3.6.1.4.1.311.2.6.1": "SpcRelaxedPEMarkerCheck",
    "1.3.6.1.4.1.311.2.6.2": "SpcEncryptedDigestRetryCount",
    "1.3.6.1.4.1.311.20.1": "CTL Usage",
    "1.3.6.1.4.1.311.20.2.1": "Certificate Request Agent",
    "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
    "1.3.6.1.4.1.311.21.19": "Directory Service Email Replication",
    "1.3.6.1.4.1.311.21.5": "Private Key Archival",
    "1.3.6.1.4.1.311.21.6": "Key Recovery Agent",
    "1.3.6.1.4.1.311.61.1.1": "Kernel Mode Code Signing",
    "1.3.6.1.4.1.311.61.4.1": "Early Launch Antimalware Driver",
    "1.3.6.1.4.1.311.61.5.1": "HAL Extension",
    "1.3.6.1.4.1.311.64.1.1": "Domain Name System (DNS) Server Trust",
    "1.3.6.1.4.1.311.76.3.1": "Windows Store",
    "1.3.6.1.4.1.311.76.5.1": "Dynamic Code Generator",
    "1.3.6.1.4.1.311.76.6.1": "Windows Update",
    "1.3.6.1.4.1.311.76.8.1": "Microsoft Publisher",
    "1.3.6.1.4.1.311.80.1": "Document Encryption",
    "1.3.6.1.5.2.3.4": "PKINIT Client Authentication",
    "1.3.6.1.5.2.3.5": "KDC Authentication",
    "1.3.6.1.5.5.7.3.1": "Server Authentication",
    "1.3.6.1.5.5.7.3.2": "Client Authentication",
    "1.3.6.1.5.5.7.3.3": "Code Signing",
    "1.3.6.1.5.5.7.3.4": "Secure Email",
    "1.3.6.1.5.5.7.3.5": "IP security end system",
    "1.3.6.1.5.5.7.3.6": "IP security tunnel termination",
    "1.3.6.1.5.5.7.3.7": "IP security user]",
    "1.3.6.1.5.5.7.3.8": "Time Stamping",
    "1.3.6.1.5.5.7.3.9": "OCSP Signing",
    "1.3.6.1.5.5.8.2.2": "IP security IKE intermediate",
    "2.23.133.8.1": "Endorsement Key Certificate",
    "2.23.133.8.2": "Platform Certificate",
    "2.23.133.8.3": "Attestation Identity Key Certificate",
    "2.23.133.8.3": "Attestation Identity Key Certificate",
    "2.5.29.37.0": "Any Purpose"
}


# Auxiliar functions
def convert_domain_str_to_dn(domain_str):
    """
    Convert domain string to distinguished name format.

    Args:
        domain_str (str): Domain name in format 'example.com'

    Returns:
        str: Distinguished name format 'DC=example,DC=com'
    """
    components = domain_str.split(".")
    domain_dn = ",".join([f"DC={component}" for component in components])
    return domain_dn


def convert_sid_bytes_to_str(sid_bytes):
    """
    Convert SID bytes to readable string format.

    Args:
        sid_bytes (bytes): Raw SID bytes from Active Directory

    Returns:
        str: SID string in format 'S-1-5-...'
    """
    revision, sub_authority_count = struct.unpack('<BB', sid_bytes[:2])
    authority = struct.unpack('>Q', b'\x00\x00' + sid_bytes[2:8])[0]
    sub_authorities = []

    for i in range(sub_authority_count):
        sub_authority = struct.unpack('<L', sid_bytes[8 + i * 4:12 + i * 4])[0]
        sub_authorities.append(sub_authority)

    sid_string = f'S-{revision}-{authority}'
    for sub_authority in sub_authorities:
        sid_string += f'-{sub_authority}'

    return sid_string


def convert_guid_bytes_to_str(guid_bytes):
    """
    Convert GUID bytes to readable string format.

    Args:
        guid_bytes (bytes): Raw GUID bytes from Active Directory

    Returns:
        str: GUID string in format 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
    """
    data = struct.unpack('<IHH8B', guid_bytes)
    return '{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}'.format(*data)


def get_sam_account_name_from_sid(connection, domain, sid_str):
    """
    Retrieve the SAM account name for a given SID from Active Directory.
    
    Args:
        connection: LDAP connection object
        domain (str): Domain name
        sid_str (str): SID string in format S-1-5-...
        
    Returns:
        str: SAM account name for the given SID, or an empty string if not found
    """
    try:
        sam_account_name = ""
        search_base = f"{convert_domain_str_to_dn(domain)}"
        search_filter = f"(objectSid={sid_str})"
        attributes = ["sAMAccountName"]
        search_scope = "SUBTREE"

        if connection.search(
            search_base, search_filter, attributes=attributes, search_scope=search_scope
        ) and len(connection.entries) > 0:  # This LDAP search should only return one result
            entry = connection.entries[0]
            sam_account_name = str(entry["sAMAccountName"])

        return sam_account_name

    except Exception as e:
        print(f"{COLORS['red']}[-] {COLORS['white']}{e}")
        return ""


def get_sid_from_sam_account_name(connection, domain, sam_str):
    """
    Retrieve the SID for a given SAM account name from Active Directory.
    
    Args:
        connection: LDAP connection object
        domain (str): Domain name
        sam_str (str): SAM account name
        
    Returns:
        str: SID string in format S-1-5-... for the given SAM account name,
            or an empty string if not found
    """
    try:
        sid = ""
        search_base = f"{convert_domain_str_to_dn(domain)}"
        search_filter = f"(sAMAccountName={sam_str})"
        attributes = ["objectSid"]
        search_scope = "SUBTREE"

        if connection.search(
            search_base, search_filter, attributes=attributes, search_scope=search_scope
        ) and len(connection.entries) > 0:  # This LDAP search should only return one result
            entry = connection.entries[0]
            sid = str(entry["objectSid"])

        return sid

    except Exception as e:
        print(f"{COLORS['red']}[-] {COLORS['white']}{e}")
        return ""


def establish_ldap_connection(domain, user, password="", dc_ip="", pth=False):
    """
    Establish LDAP connection to the domain controller.

    Args:
        domain (str): Domain name
        user (str): Username for authentication
        password (str, optional): Password for authentication. Defaults to "".
        dc_ip (str, optional): Domain controller IP address. Defaults to "".
        pth (bool, optional): Whether to use pass-the-hash authentication. Defaults to False.

    Returns:
        Connection | None: LDAP connection object if successful, otherwise None
    """
    try:
        if dc_ip == "":
            print(f"\n{COLORS['blue']}[*] {COLORS['white']}Resolving {domain}...")
            dc_ip = socket.gethostbyname(domain)
            print(f"{COLORS['green']}[+] {COLORS['white']}Resolved {domain} to {dc_ip}")

        print(f"\n{COLORS['blue']}[*] {COLORS['white']}Establishing LDAP connection as {user}...")

        server = Server(f"ldap://{dc_ip}", get_info=ALL)

        if not pth:
            connection = Connection(
                server,
                user=f"{domain}\\{user}",
                password=password,
                authentication=NTLM,
                auto_bind=True,
            )
        else:
            connection = Connection(
                server,
                user=f"{domain}\\{user}",
                password=f"aad3b435b51404eeaad3b435b51404ee:{password}",
                authentication=NTLM,
                auto_bind=True,
            )

        if connection.bind():
            print(f"{COLORS['green']}[+] {COLORS['white']}Successfully established LDAP connection")
            return connection

    except Exception as e:
        print(f"{COLORS['red']}[-] {COLORS['white']}{e}")
    return None
# Enumeration functions
def enumerate(user, password, ca="", template="", dc_ip="", enabled=False, print_only_vulnerable=False, verbose=False, pth=False, skip_ca_permissions=False):
    """
    Orchestrate ESC1 enumeration across LDAP, CAs, and templates.

    Steps:
    1) Establish LDAP connection.
    2) Enumerate low-privileged, administrative, and user SIDs.
    3) Enumerate Certification Authorities and their configurations (best effort).
    4) Enumerate Certificate Templates and analyze ESC1 conditions.
    5) Print results (optionally filtered/verbose).

    Args:
        user (str): Username in format 'user@domain.com'
        password (str): Password or NTLM hash (when using PtH)
        ca (str): Specific CA to enumerate (optional)
        template (str): Specific template to enumerate (optional)
        dc_ip (str): Domain controller IP address (optional)
        enabled (bool): If True, enumerate only templates enabled on some CA
        print_only_vulnerable (bool): If True, print only potentially vulnerable templates
        verbose (bool): If True, include detailed ACE information
        pth (bool): If True, use Pass-the-Hash authentication
        skip_ca_permissions (bool): If True, skip CA permissions enumeration via RPC
    """
    domain = user.split("@")[1]
    user = user.split("@")[0]

    ldap_connection = establish_ldap_connection(domain, user, password, dc_ip, pth)

    low_priv_sids = enum_low_priv_sids(ldap_connection, domain)

    admin_sids = enum_admin_sids(ldap_connection, domain)

    user_sids = enum_user_sids(ldap_connection, domain, user, low_priv_sids)

    certification_authorities = enumerate_certification_authorities(ldap_connection, domain, user, password, ca, pth, skip_ca_permissions)

    certificate_templates = enumerate_certificate_templates(ldap_connection, domain, certification_authorities, user_sids, admin_sids, enabled, template)

    print_enumeration_output(certification_authorities, certificate_templates, user_sids, admin_sids, domain, ldap_connection, print_only_vulnerable, verbose)


def enum_low_priv_sids(connection, domain):
    """
    Enumerate low-privileged SIDs from Active Directory.
    This function retrieves common low-privileged security identifiers including
    Everyone, Authenticated Users, Users, Domain Users, and Domain Computers.
    
    Args:
        connection: LDAP connection object
        domain (str): Domain name
        
    Returns:
        dict: Dictionary mapping SIDs to their display names for low-privileged accounts
    """
    try:
        low_priv_sids = {
            "S-1-1-0": "Everyone",
            "S-1-5-11": "Authenticated Users",
            "S-1-5-32-545": "Users"
        }

        low_priv_sam_account_names = ["Domain Users", "Domain Computers"]
        for sam in low_priv_sam_account_names:
            sid = get_sid_from_sam_account_name(connection, domain, sam)
            if sid:  # Only add if SID is not empty
                low_priv_sids[sid] = sam

        ALL_SID.update(low_priv_sids)

        return low_priv_sids

    except Exception as e:
        print(f"{COLORS['red']}[-] {COLORS['white']}{e}")
        return {}


def enum_admin_sids(connection, domain):
    """
    Enumerate administrative SIDs from Active Directory.
    
    This function retrieves administrative security identifiers including
    Enterprise Domain Controllers, Administrators, Domain Admins, and other
    administrative groups.
    
    Args:
        connection: LDAP connection object
        domain (str): Domain name
        
    Returns:
        dict: Dictionary mapping SIDs to their display names for administrative accounts
    """
    try:
        admin_sids = {
            "S-1-5-9": "Enterprise Domain Controllers",
            "S-1-5-32-544": "Administrators"
        }

        admin_sam_account_names = [
            "Enterprise Read-only Domain Controllers",
            "Administrator",
            "Krbtgt",
            "Domain Admins",
            "Domain Controllers",
            "Schema Admins",
            "Enterprise Admins",
            "Read-only Domain Controllers",
        ]
        for sam in admin_sam_account_names:
            sid = get_sid_from_sam_account_name(connection, domain, sam)
            if sid:  # Only add if SID is not empty
                admin_sids[sid] = sam

        ALL_SID.update(admin_sids)

        return admin_sids

    except Exception as e:
        print(f"{COLORS['red']}[-] {COLORS['white']}{e}")
        return {}


def enum_user_sids(connection, domain, user, low_priv_sids):
    """
    Enumerate all SIDs associated with a user account.
    
    This function retrieves the user's direct SID, primary group SID, and all
    group memberships (including nested groups) from Active Directory.
    
    Args:
        connection: LDAP connection object
        domain (str): Domain name
        user (str): Username
        low_priv_sids (dict): Dictionary of low-privileged SIDs to include
        
    Returns:
        dict: Dictionary mapping SIDs to their display names for the user and their groups
    """
    try:
        print(f"\n{COLORS['blue']}[*] {COLORS['white']}Getting user SIDs...")
        user_sids = {}

        search_base = f"{convert_domain_str_to_dn(domain)}"
        search_filter = f"(sAMAccountName={user})"
        attributes = ["objectSid", "memberOf", "primaryGroupId"]
        search_scope = "SUBTREE"

        if connection.search(
            search_base, search_filter, attributes=attributes, search_scope=search_scope
        ) and len(connection.entries) > 0:  # This LDAP search should only return one result
            current_user = connection.entries[0]

            current_user_sid = str(current_user["objectSid"])
            user_sids[current_user_sid] = user

            primary_group_sid = f"{'-'.join(current_user_sid.split('-')[:-1])}-{str(current_user['primaryGroupId'])}"
            search_filter = f"(objectSid={primary_group_sid})"
            attributes = ["sAMAccountName"]
            if connection.search(search_base, search_filter, attributes=attributes, search_scope=search_scope) and len(connection.entries) > 0:
                primary_group_name = str(connection.entries[0]["sAMAccountName"])
                user_sids[primary_group_sid] = primary_group_name
            else:
                user_sids[primary_group_sid] = ""

            processed_groups = set()
            groups = list(current_user["memberOf"])
            while groups:
                group_dn = groups.pop(0)
                if group_dn in processed_groups:
                    continue

                search_filter = f"(distinguishedName={group_dn})"
                attributes = ["objectSid", "memberOf", "sAMAccountName"]

                if connection.search(search_base, search_filter, attributes=attributes, search_scope=search_scope) and len(connection.entries) > 0:
                    group = connection.entries[0]

                    group_sid = str(group["objectSid"])
                    group_name = str(group["sAMAccountName"])
                    user_sids[group_sid] = group_name

                    indirect_membership = group["memberOf"]
                    if indirect_membership:
                        for indirect_group_dn in indirect_membership:
                            if indirect_group_dn not in processed_groups:
                                groups.append(indirect_group_dn)

        for sid, name in low_priv_sids.items():
            if sid not in user_sids:
                user_sids[sid] = name

        print(f"{COLORS['green']}[+] {COLORS['white']}User SIDs:")
        for sid, name in user_sids.items():
            print(f"{TAB * 3}{domain}\\{name} -> {sid}")

        ALL_SID.update(user_sids)

        return user_sids

    except Exception as e:
        print(f"{COLORS['red']}[-] {COLORS['white']}{e}")
        return {}


def enumerate_certification_authorities(connection, domain, user, password, ca="", pth=False, skip_ca_permissions=False):
    """
    Enumerate certification authorities from Active Directory.
    
    This function searches for certification authorities in the domain and retrieves
    their basic information including DNS hostname, certificate DN, and supported
    certificate templates.
    
    Args:
        connection: LDAP connection object
        domain (str): Domain name
        user (str): Username for authentication
        password (str): Password or NTLM hash
        ca (str): Specific CA name to search for (optional)
        pth (bool): Whether using pass-the-hash authentication
        skip_ca_permissions (bool): Whether to skip CA permissions enumeration via RPC
        
    Returns:
        dict: CA information including DNS, DN, supported templates, configuration bytes, and parsed permissions
    """
    try:
        certification_authorities = {}
        ca_configuration = "\x00\x00\x00\x00"
        ca_permissions = {0x00000001: set(), 0x00000002: set(), 0x00000004: set(), 0x00000008: set(), 0x00000100: set(), 0x00000200: set()}

        if ca != "":
            print(f"\n{COLORS['blue']}[*] {COLORS['white']}Searching certification authority...")
            search_base = (
                f"CN={ca},CN=Enrollment Services,CN=Public Key Services,"
                f"CN=Services,CN=Configuration,{convert_domain_str_to_dn(domain)}"
            )
        else:
            print(f"\n{COLORS['blue']}[*] {COLORS['white']}Searching certification authorities...")
            search_base = (
                f"CN=Enrollment Services,CN=Public Key Services,CN=Services,"
                f"CN=Configuration,{convert_domain_str_to_dn(domain)}"
            )

        search_filter = "(objectClass=pKIEnrollmentService)"
        attributes = ["name", "dNSHostName", "cACertificateDN", "certificateTemplates"]
        search_scope = "SUBTREE"

        if connection.search(search_base, search_filter, attributes=attributes, search_scope=search_scope):
            if len(connection.entries) == 0:
                print(f"{COLORS['red']} No certification authority found")

            elif len(connection.entries) == 1:
                print(f"{COLORS['green']}[+] {COLORS['white']}Found 1 certification authority:")

                ca = connection.entries[0]

                ca_name = str(ca["name"]) if "name" in ca else ""
                ca_dns_hostname = str(ca["dNSHostName"]) if "dNSHostName" in ca else ""
                ca_certificate_dn = str(ca["cACertificateDN"]) if "cACertificateDN" in ca else ""
                ca_certificate_templates = list(ca["certificateTemplates"]) if "certificateTemplates" in ca else ""

                certification_authorities[ca_name] = {"ca_dns_hostname": ca_dns_hostname, "ca_certificate_dn": ca_certificate_dn, "ca_certificate_templates": ca_certificate_templates, "ca_configuration": ca_configuration, "ca_permissions": ca_permissions}

            else:
                print(f"{COLORS['green']}[+] {COLORS['white']}Found {len(connection.entries)} certification authorities:")

                for ca in connection.entries:
                    ca_name = str(ca["name"]) if "name" in ca else ""
                    ca_dns_hostname = str(ca["dNSHostName"]) if "dNSHostName" in ca else ""
                    ca_certificate_dn = str(ca["cACertificateDN"]) if "cACertificateDN" in ca else ""
                    ca_certificate_templates = list(ca["certificateTemplates"]) if "certificateTemplates" in ca else ""

                    certification_authorities[ca_name] = {
                        "ca_dns_hostname": ca_dns_hostname,
                        "ca_certificate_dn": ca_certificate_dn,
                        "ca_certificate_templates": ca_certificate_templates,
                        "ca_configuration": ca_configuration,
                        "ca_permissions": ca_permissions,
                    }

        if len(certification_authorities) > 0:
            for ca_name, _ in certification_authorities.items():
                print(f"{TAB * 3}{ca_name}")

        if not skip_ca_permissions:
            certification_authorities = enumerate_certification_authorities_configurations(connection, certification_authorities, domain, user, password, pth)
        else:
            print(f"\n{COLORS['blue']}[*] {COLORS['white']}Skipping CA permissions enumeration (--skip-ca-permissions-enum flag set)")

        return certification_authorities

    except Exception as e:
        print(f"{COLORS['red']}[-] {COLORS['white']}{e}")
        return {}


def enumerate_certification_authorities_configurations(connection, ca_dict, domain, user, password, pth=False):
    """
    Retrieve CA security configurations via RPC.
    
    This function attempts to retrieve CA security configurations using RPC calls
    to the Windows Registry. It tries to get the Security value from the CA's
    registry configuration and parses the permissions.
    
    Args:
        connection: LDAP connection object
        ca_dict (dict): Dictionary containing CA information
        domain (str): Domain name
        user (str): Username for authentication
        password (str): Password or NTLM hash
        pth (bool): Whether using pass-the-hash authentication
        
    Returns:
        dict: Updated CA dictionary with CA configuration bytes and parsed permissions
    """
    username = user.split("\\")[-1]

    for ca_name, ca_info in ca_dict.items():
        subkey = f"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{ca_name}"
        value_name = "Security"
        success = False
        ca_ip = socket.gethostbyname(ca_info["ca_dns_hostname"])

        for attempt in range(2):
            if not success:
                try:
                    if attempt == 0:
                        print(f"\n{COLORS['blue']}[*] {COLORS['white']}Trying to get CA configuration for {ca_name} via RRP...")
                    else:
                        print(f"{COLORS['orange']}[!] {COLORS['white']}Trying to get CA configuration for {ca_name} via RRP (second attempt)...")

                    string_binding = f"ncacn_np:{ca_ip}[\\pipe\\winreg]"
                    rpc_transport = transport.DCERPCTransportFactory(string_binding)

                    if not pth:
                        rpc_transport.set_credentials(username, password, domain)
                    else:
                        rpc_transport.set_credentials(username, "", domain, nthash=password)

                    dce = rpc_transport.get_dce_rpc()
                    dce.connect()
                    dce.bind(rrp.MSRPC_UUID_RRP)

                    ans = rrp.hOpenLocalMachine(dce)
                    hklm_handle = ans["phKey"]

                    ans = rrp.hBaseRegOpenKey(dce, hklm_handle, subkey, samDesired=rrp.KEY_READ)
                    subkey_handle = ans["phkResult"]

                    ans = rrp.hBaseRegQueryValue(dce, subkey_handle, value_name)
                    value_data = ans[1]


                    rrp.hBaseRegCloseKey(dce, subkey_handle)
                    rrp.hBaseRegCloseKey(dce, hklm_handle)
                    dce.disconnect()

                    ca_info["ca_configuration"] = value_data

                    ca_info["ca_permissions"] = enumerate_certification_authorities_permissions(ca_info["ca_permissions"], value_data)

                    success = True

                    print(f"{COLORS['green']}[+] {COLORS['white']}Successfully got CA configuration for {ca_name}:")

                    for permission, sid_set in ca_info["ca_permissions"].items():
                        if len(sid_set) == 0:
                            continue
                        print(f"{TAB * 3}{CA_PERMISSIONS_ACCESS_MASKS[permission][0]}:")
                        for sid in sid_set:
                            if sid not in ALL_SID:
                                ALL_SID.update({sid: get_sam_account_name_from_sid(connection, domain, sid)})
                            print(f"{TAB * 4}{domain}\\{ALL_SID[sid]} -> {sid}")

                except Exception as e:
                    if attempt == 0:
                        time.sleep(1)
                    if attempt == 1:
                        ca_info["ca_configuration"] = b""
                        ca_info["ca_permissions"] = dict()

            if not success and attempt == 1:
                    print(f"{COLORS['red']}[-] {COLORS['white']}Could not get CA configurations for {ca_name} via RRP")

    return ca_dict


def enumerate_certification_authorities_permissions(ca_permissions_dict, permissions_bytes):
    """
    Parse CA security permissions from binary security descriptor.
    
    This function parses the binary security descriptor data to extract
    owner SID, group SID, and DACL entries that define CA permissions.
    
    Args:
        ca_permissions_dict (dict): Dictionary to store parsed permissions
        permissions_bytes (bytes): Binary security descriptor data
        
    Returns:
        dict: Updated permissions dictionary mapping CA access masks to sets of SID strings
    """
    try:
        owner_offset, group_offset, _, dacl_offset = struct.unpack("<LLLL", permissions_bytes[4:20])

        owner_sid_bytes = permissions_bytes[owner_offset:]
        owner_sid = convert_sid_bytes_to_str(owner_sid_bytes)

        group_sid_bytes = permissions_bytes[group_offset:]
        group_sid = convert_sid_bytes_to_str(group_sid_bytes)

        if dacl_offset != 0:
            dacl_bytes = permissions_bytes[dacl_offset:]

            _, _, _, ace_count, _ = struct.unpack("<BBHHH", dacl_bytes[:8])

            current_offset = 8
            for _ in range(ace_count):
                current_offset += 4     # Skip header -> ACE type always ACCESS_ALLOWED_ACE?

                access_mask = struct.unpack("<L", dacl_bytes[current_offset:current_offset + 4])[0]

                current_offset += 4

                _, sub_authority_count = struct.unpack("<BB", dacl_bytes[current_offset:][:2])
                sid_size = 8 + (sub_authority_count * 4)
                sid_bytes = dacl_bytes[current_offset:current_offset + sid_size]
                sid = convert_sid_bytes_to_str(sid_bytes)

                # Decompose the access mask into individual permission bits
                for permission_bit in CA_PERMISSIONS_ACCESS_MASKS.keys():
                    if access_mask & permission_bit:  # Check if this permission bit is set
                        ca_permissions_dict[permission_bit].add(sid)

                current_offset += sid_size

        return ca_permissions_dict

    except Exception as e:
        print(f"{COLORS['red']}[-] {COLORS['white']}{e}")
        return ca_permissions_dict


def enumerate_certificate_templates(connection, domain, ca_dict, user_sids, privileged_sids, enum_only_enabled, template_to_enum=""):
    """
    Enumerate certificate templates from Active Directory.
    
    This function searches for certificate templates and retrieves their properties
    including enrollment flags, certificate name flags, EKUs, and security descriptors.
    It also performs vulnerability analysis for ESC1 conditions.
    
    Args:
        connection: LDAP connection object
        domain (str): Domain name
        ca_dict (dict): Dictionary containing CA information
        user_sids (dict): Dictionary of user SIDs
        privileged_sids (dict): Dictionary of privileged SIDs
        enum_only_enabled (bool): Whether to enumerate only enabled templates
        template_to_enum (str): Specific template name to search for (optional)
        
    Returns:
        dict: Template information including flags, EKUs, DACL, and ESC1 analysis annotations
    """
    try:
        enabled_certificates = {}
        for ca_name, ca_info in ca_dict.items():
            for template_name in ca_info["ca_certificate_templates"]:
                if template_name not in enabled_certificates:
                    enabled_certificates[template_name] = set()
                enabled_certificates[template_name].add(ca_name)

        certificate_templates = {}

        if template_to_enum != "":
            print(f"\n{COLORS['blue']}[*] {COLORS['white']}Searching certificate template...")
            search_base = (
                f"CN={template_to_enum},CN=Certificate Templates,CN=Public Key Services,"
                f"CN=Services,CN=Configuration,{convert_domain_str_to_dn(domain)}"
            )
        else:
            if enum_only_enabled:
                print(f"\n{COLORS['blue']}[*] {COLORS['white']}Searching enabled certificate templates...")
            else:
                print(f"\n{COLORS['blue']}[*] {COLORS['white']}Searching certificate templates...")
            search_base = (
                f"CN=Certificate Templates,CN=Public Key Services,CN=Services,"
                f"CN=Configuration,{convert_domain_str_to_dn(domain)}"
            )

        search_filter = "(objectClass=pKICertificateTemplate)"
        attributes = ["cn", "msPKI-Enrollment-Flag", "msPKI-Certificate-Name-Flag", "pkiExtendedKeyUsage", "msPKI-RA-Signature", "ntSecurityDescriptor"]
        search_scope = "SUBTREE"
        control = security_descriptor_control(sdflags=0x07)

        if connection.search(search_base, search_filter, attributes=attributes, search_scope=search_scope, controls=control):
            if len(connection.entries) == 0:
                print(f"{COLORS['red']} No certificate template found")

            else:
                for template in connection.entries:
                    template_name = str(template["cn"]) if "cn" in template else ""

                    if enum_only_enabled and template_name not in enabled_certificates:
                        continue

                    template_enabled_in = enabled_certificates[template_name] if template_name in enabled_certificates else set()
                    template_enrollment_flags = (
                        int(template["msPKI-Enrollment-Flag"].raw_values[0])
                        if "msPKI-Enrollment-Flag" in template
                        else ""
                    )  # Manager approval -> CT_FLAG_PEND_ALL_REQUESTS (0x2)
                    template_certificate_name_flags = (
                        int(template["msPKI-Certificate-Name-Flag"].raw_values[0])
                        if "msPKI-Certificate-Name-Flag" in template
                        else ""
                    )  # Requesters can specify a subjectAltName in the CSR -> CT_FLAG_ENROLEE_SUPPLIES_SUBJECT
                    template_recovery_agent_signatures = (
                        str(template["msPKI-RA-Signature"]) if "msPKI-RA-Signature" in template else ""
                    )  # Requires CSRs to be signed by an existing authorized certificate
                    template_eku_list = (
                        list(template["pkiExtendedKeyUsage"]) if "pkiExtendedKeyUsage" in template else ""
                    )  # EKUs that enable authentication -> Client Authentication, PKINIT Client Authentication, Smart Card Logon, Any Purpose, or no EKU
                    template_security_descriptor = (
                        template["ntSecurityDescriptor"].raw_values[0]
                        if "ntSecurityDescriptor" in template
                        else ""
                    )

                    template_owner, template_group, template_dacl = parse_security_descriptor(template_security_descriptor)

                    # Resolve owner and group SIDs to usernames and add to ALL_SID
                    if template_owner and template_owner not in ALL_SID:
                        ALL_SID[template_owner] = get_sam_account_name_from_sid(connection, domain, template_owner)
                    if template_group and template_group not in ALL_SID:
                        ALL_SID[template_group] = get_sam_account_name_from_sid(connection, domain, template_group)

                    certificate_templates[template_name] = {
                        "enabled_in": template_enabled_in,
                        "enrollment_flags": template_enrollment_flags,
                        "certificate_name_flags": template_certificate_name_flags,
                        "eku_list": template_eku_list,
                        "recovery_agent_signatures": template_recovery_agent_signatures,
                        "security_descriptor": template_security_descriptor,
                        "owner": template_owner,
                        "group": template_group,
                        "dacl": template_dacl,
                    }

                template_count = len(certificate_templates)
                if template_count == 1 and not enum_only_enabled:
                    print(f"{COLORS['green']}[+] {COLORS['white']}Found 1 certificate template:")
                elif template_count == 1 and enum_only_enabled:
                    print(f"{COLORS['green']}[+] {COLORS['white']}Found 1 enabled certificate template:")
                elif template_count > 1 and not enum_only_enabled:
                    print(f"{COLORS['green']}[+] {COLORS['white']}Found {template_count} certificate templates:")
                else:
                    enabled_count = len([t for t in certificate_templates.values() if t["enabled_in"]])
                    print(f"{COLORS['green']}[+] {COLORS['white']}Found {enabled_count} enabled certificate templates:")

        if len(certificate_templates) > 0:
            for template_name, template_info in certificate_templates.items():
                if enum_only_enabled and not template_info["enabled_in"]:
                    continue
                print(f"{TAB * 3}{template_name}")

        check_if_vulnerable(user_sids, privileged_sids, ca_dict, certificate_templates)

        return certificate_templates

    except Exception as e:
        print(f"{COLORS['red']}[-] {COLORS['white']}{e}")
        return {}


def parse_security_descriptor(security_descriptor_bytes):
    """
    Parse Windows security descriptor from binary data.
    
    This function extracts the owner SID, group SID, and DACL from a
    binary security descriptor. It parses the header structure and
    delegates DACL parsing to a separate function.
    
    Args:
        security_descriptor_bytes (bytes): Binary security descriptor data
        
    Returns:
        tuple[str, str, list]: (owner_sid, group_sid, dacl) where dacl is [revision, ace_list]
    """
    # Offsets (ignoring SACL)
    owner_offset, group_offset, _, dacl_offset = struct.unpack("<LLLL", security_descriptor_bytes[4:20])

    # Get owner and group SIDs
    owner_sid = convert_sid_bytes_to_str(security_descriptor_bytes[owner_offset:])
    group_sid = convert_sid_bytes_to_str(security_descriptor_bytes[group_offset:])

    # If there is a DACL, extract info from it
    if dacl_offset != 0:
        dacl_bytes = security_descriptor_bytes[dacl_offset:]
        acl_revision, ace_list = parse_dacl(dacl_bytes)
        dacl = [acl_revision, ace_list]

    return owner_sid, group_sid, dacl


def parse_dacl(dacl_bytes):
    """
    Parse DACL (Discretionary Access Control List) from binary data.
    
    This function parses the DACL structure to extract ACE (Access Control Entry)
    information including ACE type, flags, access mask, and SID. It handles
    both standard ACEs and object ACEs with GUIDs.
    
    Args:
        dacl_bytes (bytes): Binary DACL data
        
    Returns:
        tuple[int, list[dict]]: (acl_revision, ace_list) where ace_list contains parsed ACE dictionaries
    """
    # Read first 4 bytes of the DACL to get ACL information (ignoring sbz1, ACL size, and sbz2)
    acl_revision, _, _, ace_count, _ = struct.unpack("<BBHHH", dacl_bytes[:8])

    # Define initial offset (first 4 bytes already read)
    current_offset = 8

    # Iterate over ACEs
    ace_list = list()
    for _ in range(ace_count):
        ace = dict()

        # Read ACE header
        ace_type, ace_flags, ace_size = struct.unpack("<BBH", dacl_bytes[current_offset:current_offset + 4])
        ace["type"] = ACE_TYPES[ace_type]
        ace["flags"] = ace_flags


        # Read ACE
        ace_bytes = dacl_bytes[current_offset:current_offset + ace_size]

        # Read next 4 bytes to get the access mask
        aux_offset = 4
        access_mask = struct.unpack("<L", ace_bytes[aux_offset:aux_offset + 4])[0]
        ace["access_mask"] = access_mask

        # Check if object ACE and define SID offset
        object_type = inherited_object_type = None
        if ace["type"][1] == 4:
            aux_offset += 4
            object_flags = struct.unpack("<L", ace_bytes[aux_offset:aux_offset + 4])[0]

            aux_offset += 4

            if object_flags & 0x1:
                object_type = True
                object_type_guid = ace_bytes[aux_offset:aux_offset + 16]
                guid = convert_guid_bytes_to_str(object_type_guid)
                ace["object_guid"] = guid
                sid_offset = aux_offset + 16

            if object_flags & 0x2:
                inherited_object_type = True
                inherited_object_type_guid = ace_bytes[aux_offset:aux_offset + 16]
                guid = convert_guid_bytes_to_str(inherited_object_type_guid)
                ace["inherited_object"] = guid
                sid_offset = aux_offset + 16

        # Read SID
        else:
            sid_offset = aux_offset + 4

        _, sub_authority_count = struct.unpack("<BB", ace_bytes[sid_offset:][:2])
        sid_size = 8 + (sub_authority_count * 4)     # 8 bytes (header) + 4 bytes per sub authority
        sid_bytes = ace_bytes[sid_offset:sid_offset + sid_size]
        sid = convert_sid_bytes_to_str(sid_bytes)

        ace["sid"] = sid

        ace_list.append(ace)

        current_offset += ace_size

    return acl_revision, ace_list


def check_if_vulnerable(user_sids, privileged_sids, certification_authorities, certificate_templates):
    """
    Analyze certificate templates for ESC1-related conditions and annotate results.

    This function evaluates each template against six conditions relevant to ESC1:
    1) CA enrollment permissions for the current user SIDs on CAs where the
       template is enabled (records whether user can enroll and which SIDs allow it).
    2) Manager approval is NOT required for enrollment.
    3) Requesters can supply subjectAltName in the CSR (SAN allowed).
    4) Recovery agent (RA) signature is NOT required.
    5) Template defines EKUs that enable authentication (e.g., Client Auth, PKINIT,
       Smart Card Logon, Any Purpose).
    6) Template DACL allows low-privileged SIDs to enroll (DS_CONTROL_ACCESS on
       template or equivalent object-specific ACE).

    Classification note:
    - The function marks a template as "potentially_vulnerable_to_esc1" when
      conditions (2) through (6) are met. The CA enrollment check (1) is performed
      and stored for reporting purposes, but is not required for the
      "potentially vulnerable" classification and should be verified separately
      against CA permissions.

    Args:
        user_sids (dict): Mapping of user/group SIDs relevant to the current context.
        privileged_sids (dict): Mapping of privileged SIDs to exclude from low-priv checks.
        certification_authorities (dict): CA data including permissions and enabled templates.
        certificate_templates (dict): Template metadata and security descriptor details.

    Returns:
        None: Mutates `certificate_templates` entries with analysis fields, including:
            - user_can_request_certificates (bool)
            - ca_enrollment_allowed_sids (set)
            - enabled_enrollment_flags (list[int])
            - requires_manager_approval (bool)
            - enabled_certificate_name_flags (list[int])
            - allows_san (bool)
            - number_of_recovery_agent_signatures_required (int)
            - requires_recovery_agent_signature (bool)
            - defines_authentication_eku (bool)
            - low_privileged_sids_allowed_to_enroll (set)
            - potentially_vulnerable_to_esc1 (bool, when applicable)
    """
    for certificate_template_name, certificate_template_info_dict in certificate_templates.items():
        # 1st condition -> CA grants user enrollment rights
        user_can_request_certificates, ca_enrollment_allowed_sids = check_ca_enrollment(user_sids, certification_authorities, certificate_template_info_dict)
        certificate_template_info_dict["user_can_request_certificates"] = user_can_request_certificates
        certificate_template_info_dict["ca_enrollment_allowed_sids"] = ca_enrollment_allowed_sids

        # 2nd condition -> Does not require manager approval
        requires_manager_approval, enabled_enrollment_flags = check_enrollment_flags(certificate_template_info_dict)
        certificate_template_info_dict["enabled_enrollment_flags"] = enabled_enrollment_flags
        certificate_template_info_dict["requires_manager_approval"] = requires_manager_approval

        # 3rd condition -> Requesters can specify a subjectAltName in the CSR
        allows_san, enabled_certificate_name_flags = check_certificate_name_flags(certificate_template_info_dict)
        certificate_template_info_dict["enabled_certificate_name_flags"] = enabled_certificate_name_flags
        certificate_template_info_dict["allows_san"] = allows_san

        # 4th condition -> Recovery agent signature is not required
        requires_recovery_agent_signature, number_of_recovery_agent_signatures_required = check_recovery_agent_signatures(certificate_template_info_dict)
        certificate_template_info_dict["number_of_recovery_agent_signatures_required"] = number_of_recovery_agent_signatures_required
        certificate_template_info_dict["requires_recovery_agent_signature"] = requires_recovery_agent_signature

        # 5th condition -> EKUs that enable authentication
        defines_authentication_eku = check_ekus(certificate_template_info_dict)
        certificate_template_info_dict["defines_authentication_eku"] = defines_authentication_eku

        # 6th condition -> Overly permissive security descriptor
        low_privileged_sids_allowed_to_enroll = check_dacl(certificate_template_info_dict, privileged_sids)
        certificate_template_info_dict["low_privileged_sids_allowed_to_enroll"] = low_privileged_sids_allowed_to_enroll

        if not requires_manager_approval and allows_san and not requires_recovery_agent_signature and defines_authentication_eku and low_privileged_sids_allowed_to_enroll:
            certificate_template_info_dict["potentially_vulnerable_to_esc1"] = True


def check_ca_enrollment(user_sids, ca_dict, template_info_dict):
    """
    Check if user has enrollment permissions on the CA.
    
    This function verifies whether the user has enrollment permissions
    (0x00000200) on the certification authorities that support the template.
    
    Args:
        user_sids (dict): Dictionary of user SIDs
        ca_dict (dict): Dictionary containing CA information
        template_info_dict (dict): Template information dictionary
        
    Returns:
        tuple[bool, set]: (user_can_request_certificates, ca_enrollment_allowed_sids)
    """
    user_can_request_certificates = False
    ca_enrollment_allowed_sids = set()

    for certification_authority in template_info_dict["enabled_in"]:
        ca_permissions = ca_dict[certification_authority]["ca_permissions"]
        # Check if CA permissions were successfully enumerated and contains the Enroll permission
        if ca_permissions and 0x00000200 in ca_permissions:
            sids_allowed_to_enroll = ca_permissions[0x00000200]
            for user_sid in user_sids:
                if user_sid in sids_allowed_to_enroll:
                    ca_enrollment_allowed_sids.add(user_sid)

    if len(ca_enrollment_allowed_sids) > 0:
        user_can_request_certificates = True

    return user_can_request_certificates, ca_enrollment_allowed_sids


def check_enrollment_flags(template_info_dict):
    """
    Check enrollment flags for manager approval requirement.
    
    This function analyzes the enrollment flags to determine if manager
    approval is required (CT_FLAG_PEND_ALL_REQUESTS = 0x00000002).
    
    Args:
        template_info_dict (dict): Template information dictionary
        
    Returns:
        tuple[bool, list[int]]: (requires_manager_approval, enabled_enrollment_flags)
    """
    enrollment_flags_bytes = template_info_dict["enrollment_flags"]
    enabled_enrollment_flags = []

    for flag, _ in ENROLLMENT_FLAGS.items():
        if enrollment_flags_bytes & flag:
            enabled_enrollment_flags.append(flag)

    requires_manager_approval = bool(enrollment_flags_bytes & 0x00000002)

    return requires_manager_approval, enabled_enrollment_flags


def check_certificate_name_flags(template_info_dict):
    """
    Check certificate name flags for subjectAltName specification.
    
    This function analyzes the certificate name flags to determine if
    requesters can specify a subjectAltName in the CSR
    (CT_FLAG_ENROLEE_SUPPLIES_SUBJECT = 0x00000001).
    
    Args:
        template_info_dict (dict): Template information dictionary
        
    Returns:
        tuple[bool, list[int]]: (allows_san, enabled_certificate_name_flags)
    """
    certificate_name_flags_bytes = template_info_dict["certificate_name_flags"]
    enabled_certificate_name_flags = []

    for flag, _ in CERTIFICATE_NAME_FLAGS.items():
        if certificate_name_flags_bytes & flag:
            enabled_certificate_name_flags.append(flag)

    allows_san = bool(certificate_name_flags_bytes & 0x00000001)

    return allows_san, enabled_certificate_name_flags


def check_recovery_agent_signatures(template_info_dict):
    """
    Check if recovery agent signature is required.
    
    This function determines whether the template requires CSRs to be
    signed by an existing authorized certificate (recovery agent).
    
    Args:
        template_info_dict (dict): Template information dictionary
        
    Returns:
        tuple[bool, int]: (requires_recovery_agent_signature, number_of_recovery_agent_signatures_required)
    """
    number_of_recovery_agent_signatures_required = int(template_info_dict["recovery_agent_signatures"])
    requires_recovery_agent_signature = True if number_of_recovery_agent_signatures_required > 0 else False

    return requires_recovery_agent_signature, number_of_recovery_agent_signatures_required


def check_ekus(template_info_dict):
    """
    Check if template defines EKUs that enable authentication.
    
    This function checks if the template includes Extended Key Usages that
    enable authentication, such as Client Authentication, PKINIT Client
    Authentication, Smart Card Logon, or Any Purpose.
    
    Args:
        template_info_dict (dict): Template information dictionary
        
    Returns:
        bool: True if template defines authentication EKUs, False otherwise
    """
    defines_authentication_eku = False
    authentication_ekus = ["1.3.6.1.4.1.311.20.2.2", "1.3.6.1.5.2.3.4", "1.3.6.1.5.5.7.3.2", "2.5.29.37.0"]

    if len(template_info_dict["eku_list"]) == 0:
        defines_authentication_eku = False
    else:
        for eku in template_info_dict["eku_list"]:
            if eku in authentication_ekus:
                defines_authentication_eku = True
                break

    return defines_authentication_eku


def check_dacl(template_info_dict, privileged_sids):
    """
    Check DACL for low-privileged SIDs with enrollment permissions.
    
    This function analyzes the DACL to identify low-privileged SIDs that
    have enrollment permissions (DS_CONTROL_ACCESS = 0x00000100) on the
    certificate template.
    
    Args:
        template_info_dict (dict): Template information dictionary
        privileged_sids (dict): Dictionary of privileged SIDs to exclude
        
    Returns:
        set[str]: Set of low-privileged SIDs allowed to enroll
    """
    dacl = template_info_dict["dacl"][1]
    low_privileged_sids_allowed_to_enroll = set()

    for ace in dacl:
        ace_flags = ace["flags"]
        enabled_ace_flags = []
        for flag, _ in ACE_FLAGS.items():
            if ace_flags & flag:
                enabled_ace_flags.append(flag)
        ace["enabled_ace_flags"] = ace_flags

        access_mask = ace["access_mask"]
        enabled_rights = []
        for right, _ in AD_OBJECTS_ACCESS_MASKS.items():
            if access_mask & right:
                enabled_rights.append(right)
        ace["enabled_rights"] = enabled_rights

        enrollment_conditions_1 = ace["type"][2] == "ACCESS_ALLOWED_OBJECT_ACE" and bool(ace["access_mask"] & 0x00000100) and ace["object_guid"] == "0e10c968-78fb-11d2-90d4-00c04f79dc55"
        enrollment_conditions_2 = ace["type"][2] == "ACCESS_ALLOWED_ACE" and bool(ace["access_mask"] & 0x00000100)
        if enrollment_conditions_1 or enrollment_conditions_2:
            ace["ace_allows_enrollment"] = True
            if ace["sid"] not in privileged_sids:
                low_privileged_sids_allowed_to_enroll.add(ace["sid"])

    return low_privileged_sids_allowed_to_enroll

def print_enumeration_output(certification_authorities_dict, certificate_templates_dict, user_sids, privileged_sids, domain, connection, print_only_vulnerable, verbose):
    """
    Print comprehensive enumeration results in a formatted output.
    
    This function displays the results of the ESC1 vulnerability scan,
    including CA information, template details, and vulnerability analysis.
    It highlights potentially vulnerable templates and provides detailed
    information about security descriptors and permissions.
    
    Args:
        certification_authorities_dict (dict): Dictionary containing CA information
        certificate_templates_dict (dict): Dictionary containing template information
        user_sids (dict): Dictionary of user SIDs
        privileged_sids (dict): Dictionary of privileged SIDs
        domain (str): Domain name
        connection: LDAP connection object
        print_only_vulnerable (bool): Whether to print only vulnerable templates
        verbose (bool): Whether to print detailed ACE information
        
    Returns:
        None: Prints formatted output to console
    """
    print(f"\n{COLORS['green']}[+] {COLORS['white']}Enumeration output:\n")

    print(f"\n{COLORS['cyan']}Certification Authorities:")
    count = 1
    for ca_name, ca_info in certification_authorities_dict.items():
        print(f"{TAB}{COLORS['cyan']}{count}")

        print(f"{TAB * 2}{COLORS['cyan']}CA Name -> {COLORS['white']}{ca_name}")

        print(f"{TAB * 2}{COLORS['cyan']}CA DNS -> {COLORS['white']}{ca_info['ca_dns_hostname']}")

        print(f"{TAB * 2}{COLORS['cyan']}CA Distinguished Name -> {COLORS['white']}{ca_info['ca_certificate_dn']}")

        if ca_info["ca_permissions"]:
            print(f"{TAB * 2}{COLORS['cyan']}CA Permissions")
            for permission, sid_set in ca_info["ca_permissions"].items():
                if len(sid_set) == 0:
                    continue
                print(f"{TAB * 3}{COLORS['cyan']}{permission:#010x} {CA_PERMISSIONS_ACCESS_MASKS[permission][0]} -> {COLORS['white']}{CA_PERMISSIONS_ACCESS_MASKS[permission][1]}")
                for sid in sid_set:
                    if permission == 0x00000200:
                        print(f"{TAB * 4}{COLORS['orange']}{domain}\\{ALL_SID[sid]} ({sid})")
                    else:
                        print(f"{TAB * 4}{domain}\\{ALL_SID[sid]} ({sid})")

        else:
            print(f"{TAB * 2}{COLORS['cyan']}CA Permissions")
            print(f"{TAB * 3}{COLORS['white']}Could not enumerate CA permissions")

        count += 1

    print(f"\n{COLORS['cyan']}Certificate Templates:")
    count = 1
    for template_name, template_info in certificate_templates_dict.items():
        if print_only_vulnerable and "potentially_vulnerable_to_esc1" not in template_info:
            continue

        print(f"{TAB}{COLORS['cyan']}{count}")

        if "potentially_vulnerable_to_esc1" not in template_info:
            print(f"{TAB * 2}{COLORS['cyan']}Template Name -> {COLORS['white']}{template_name}")
        else:
            print(f"{TAB * 2}{COLORS['cyan']}Template Name -> {COLORS['white']}{template_name}")
            print(
                f"{TAB * 3}{COLORS['red']}Potentially vulnerable to ESC1 (check CA permissions to confirm "
                f"if low-priv users with enrollment permissions can request templates)"
            )

        ca_str = ""
        for ca in template_info["enabled_in"]:
            ca_str += f"{ca}, "
        print(f"{TAB * 2}{COLORS['cyan']}CAs -> {COLORS['white']}{ca_str[:-2]}")

        print(f"{TAB * 2}{COLORS['cyan']}Enrollment Flags -> {COLORS['white']}{template_info['enrollment_flags']:#010x}")
        for flag in template_info["enabled_enrollment_flags"]:
            print(f"{TAB * 3}{COLORS['white']}{ENROLLMENT_FLAGS[flag][0]}: {ENROLLMENT_FLAGS[flag][1]}")
        if 0x00000002 not in template_info["enabled_enrollment_flags"]:
            print(f"{TAB * 3}{COLORS['orange']}Manager approval is not required")

        print(f"{TAB * 2}{COLORS['cyan']}Certificate Name Flags -> {COLORS['white']}{template_info['certificate_name_flags']:#010x}")
        for flag in template_info["enabled_certificate_name_flags"]:
            print(f"{TAB * 3}{COLORS['white']}{CERTIFICATE_NAME_FLAGS[flag][0]}: {CERTIFICATE_NAME_FLAGS[flag][1]}")
        if 0x00000001 in template_info["enabled_certificate_name_flags"]:
            print(f"{TAB * 3}{COLORS['orange']}Requesters can specify a subjectAltName in the CSR")

        print(f"{TAB * 2}{COLORS['cyan']}Signatures Required -> {COLORS['white']}{template_info['number_of_recovery_agent_signatures_required']}")
        if template_info["number_of_recovery_agent_signatures_required"] == 0:
            print(f"{TAB * 3}{COLORS['orange']}Recovery agent signature is not required")

        print(f"{TAB * 2}{COLORS['cyan']}Extended Key Usages:")
        for eku in template_info["eku_list"]:
            eku_description = EKUS.get(eku, "Unknown EKU")
            print(f"{TAB * 3}{COLORS['white']}{eku}: {eku_description}")
        if template_info["defines_authentication_eku"]:
            print(f"{TAB * 3}{COLORS['orange']}EKUs enable authentication")

        print(f"{TAB * 2}{COLORS['cyan']}Security Descriptor Audit:")
        owner_name = ALL_SID.get(template_info['owner'], 'Unknown')
        group_name = ALL_SID.get(template_info['group'], 'Unknown')
        print(f"{TAB * 3}{COLORS['cyan']}Owner -> {COLORS['white']}{domain}\\{owner_name} ({template_info['owner']})")
        print(f"{TAB * 3}{COLORS['cyan']}Group -> {COLORS['white']}{domain}\\{group_name} ({template_info['group']})")

        dacl = template_info["dacl"]
        print(f"{TAB * 2}{COLORS['cyan']}DACL audit:")
        print(f"{TAB * 3}{COLORS['cyan']}ACL Revision -> {COLORS['white']}{dacl[0]} ({ACL_REVISIONS[dacl[0]][1]})")
        print(f"{TAB * 3}{COLORS['cyan']}ACE Count -> {COLORS['white']}{len(dacl[1])}")
        for ace_count in range(len(dacl[1])):
            ace = dacl[1][ace_count]
            print(f"{TAB * 4}{COLORS['cyan']}ACE {ace_count + 1}:")

            if ace["sid"] not in ALL_SID:
                ALL_SID.update({ace["sid"]: get_sam_account_name_from_sid(connection, domain, ace["sid"])})
            print(f"{TAB * 5}{COLORS['cyan']}SID -> {COLORS['white']}{domain}\\{ALL_SID[ace['sid']]} ({ace['sid']})")

            print(f"{TAB * 5}{COLORS['cyan']}Type -> {COLORS['white']}{ace['type'][2]} ({ace['type'][3]})")
            if ace["flags"] == 0:
                print(f"{TAB * 5}{COLORS['cyan']}Flags -> {COLORS['white']}No ACE flags are set")
            else:
                print(f"{TAB * 5}{COLORS['cyan']}Flags -> {COLORS['white']}{ace['flags']:#010x}")
                if verbose:
                    for flag in ace["enabled_ace_flags"]:
                        print(f"{TAB * 6}{COLORS['white']}{ACE_FLAGS[flag][0]}: {ACE_FLAGS[flag][1]}")

            print(f"{TAB * 5}{COLORS['cyan']}Access Mask -> {COLORS['white']}{ace['access_mask']:#010x}")
            if verbose:
                for right in ace["enabled_rights"]:
                    print(f"{TAB * 6}{COLORS['white']}{AD_OBJECTS_ACCESS_MASKS[right][0]} {AD_OBJECTS_ACCESS_MASKS[right][1]}: {AD_OBJECTS_ACCESS_MASKS[right][2]}")

            if ace["type"][2] == "ACCESS_ALLOWED_OBJECT_ACE":
                print(f"{TAB * 5}{COLORS['cyan']}Object GUID -> {COLORS['white']}{ace['object_guid']}")

            if ace["sid"] not in privileged_sids and "ace_allows_enrollment" in ace:
                print(f"{TAB * 5}{COLORS['orange']}ACE grants enrollment permissions to low privileged SID")

        count += 1


# Main function
def main():
    """
    Main entry point for the ESC1 scanner.

    This function handles command-line argument parsing and initiates
    the ESC1 vulnerability scanning process based on user-provided parameters.
    """
    parser = argparse.ArgumentParser(description="ESC1 audit tool for certificate templates\nWritten by Matheus Vilacha (https://linkedin.com/in/vilacham)")

    parser.add_argument("-u", "--user", required=True, help="User (e.g., username@domain.com)")
    parser.add_argument("-p", "--password", help="Password")
    parser.add_argument("-P", action="store_true", help="Prompt for password interactively")
    parser.add_argument("-n", "--ntlm", help="NTLM hash")
    parser.add_argument("-c", "--ca", default="", help="Certification Authority name")
    parser.add_argument("-t", "--template", default="", help="Certificate template name")
    parser.add_argument("--dc_ip", default="", help="IP address of the domain controller")
    parser.add_argument("--enabled", action="store_true", help="Print only enabled templates")
    parser.add_argument("--vulnerable", action="store_true", help="Print only vulnerable templates")
    parser.add_argument("--verbose", action="store_true", help="Print detailed information about ACEs")
    parser.add_argument("--skip-ca-permissions-enum", action="store_true", help="Skip CA permissions enumeration via RPC")

    args = parser.parse_args()

    pth = False
    if args.password:
        password = args.password
    elif args.P:
        password = getpass.getpass(prompt=f"Type {args.user}'s password: ")
    elif args.ntlm:
        password = args.ntlm
        pth = True
    else:
        print(f"{COLORS['red']}[-] {COLORS['white']}You must provide a password with -p or use -P to prompt for the password interactively, or provide a NTLM hash with -n")
        return

    if not pth:
        enumerate(
            args.user,
            password,
            args.ca,
            args.template,
            args.dc_ip,
            args.enabled,
            args.vulnerable,
            args.verbose,
            False,  # pth
            getattr(args, 'skip_ca_permissions_enum', False),
        )
    else:
        enumerate(
            args.user,
            password,
            args.ca,
            args.template,
            args.dc_ip,
            args.enabled,
            args.vulnerable,
            args.verbose,
            pth,
            getattr(args, 'skip_ca_permissions_enum', False),
        )

if __name__ == "__main__":
    main()
