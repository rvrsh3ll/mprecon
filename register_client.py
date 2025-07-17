
import os
import zlib
import requests
import argparse
from xml.etree import ElementTree as ET
from requests_toolbelt.multipart import decoder
from requests_ntlm                                      import HttpNtlmAuth
from cryptography.hazmat.primitives                     import serialization
from cryptography                                       import x509
from cryptography.x509.oid                              import NameOID
from cryptography.x509                                  import ObjectIdentifier
from cryptography.hazmat.primitives                     import hashes
from cryptography.hazmat.primitives.asymmetric          import rsa
from cryptography.hazmat.primitives.asymmetric.padding  import PKCS1v15
from datetime                                           import datetime, timedelta

# reference: https://github.com/synacktiv/SCCMSecrets
MP_INTERACTIONS_HEADERS = {
    "User-Agent": "cmhttp"
}
REGISTRATION_REQUEST_TEMPLATE = """<Data HashAlgorithm="1.2.840.113549.1.1.11" SMSID="" RequestType="Registration" TimeStamp="{date}">
<AgentInformation AgentIdentity="CCMSetup.exe" AgentVersion="5.00.8325.0000" AgentType="0" />
<Certificates><Encryption Encoding="HexBinary" KeyType="1">{encryption}</Encryption><Signing Encoding="HexBinary" KeyType="1">{signature}</Signing></Certificates>
<DiscoveryProperties><Property Name="Netbios Name" Value="{client}" />
<Property Name="FQ Name" Value="{clientfqdn}" />
<Property Name="Locale ID" Value="2057" />
<Property Name="InternetFlag" Value="0" />
</DiscoveryProperties></Data>"""
REGISTRATION_REQUEST_WRAPPER_TEMPLATE = "<ClientRegistrationRequest>{data}<Signature><SignatureValue>{signature}</SignatureValue></Signature></ClientRegistrationRequest>\x00"
SCCM_HEADER_TEMPLATE = """<Msg ReplyCompression="zlib" SchemaVersion="1.1"><Body Type="ByteRange" Length="{bodylength}" Offset="0" /><CorrelationID>{{00000000-0000-0000-0000-000000000000}}</CorrelationID><Hooks><Hook3 Name="zlib-compress" /></Hooks><ID>{{5DD100CD-DF1D-45F5-BA17-A327F43465F8}}</ID><Payload Type="inline" /><Priority>0</Priority><Protocol>http</Protocol><ReplyMode>Sync</ReplyMode><ReplyTo>direct:{client}:SccmMessaging</ReplyTo><SentTime>{date}</SentTime><SourceHost>{client}</SourceHost><TargetAddress>mp:MP_ClientRegistration</TargetAddress><TargetEndpoint>MP_ClientRegistration</TargetEndpoint><TargetHost>{sccmserver}</TargetHost><Timeout>60000</Timeout></Msg>"""
POLICY_REQUEST_HEADER_TEMPLATE = """<Msg ReplyCompression="zlib" SchemaVersion="1.1"><Body Type="ByteRange" Length="{bodylength}" Offset="0" /><CorrelationID>{{00000000-0000-0000-0000-000000000000}}</CorrelationID><Hooks><Hook2 Name="clientauth"><Property Name="AuthSenderMachine">{client}</Property><Property Name="PublicKey">{publickey}</Property><Property Name="ClientIDSignature">{clientIDsignature}</Property><Property Name="PayloadSignature">{payloadsignature}</Property><Property Name="ClientCapabilities">NonSSL</Property><Property Name="HashAlgorithm">1.2.840.113549.1.1.11</Property></Hook2><Hook3 Name="zlib-compress" /></Hooks><ID>{{041A35B4-DCEE-4F64-A978-D4D489F47D28}}</ID><Payload Type="inline" /><Priority>0</Priority><Protocol>http</Protocol><ReplyMode>Sync</ReplyMode><ReplyTo>direct:{client}:SccmMessaging</ReplyTo><SentTime>{date}</SentTime><SourceID>GUID:{clientid}</SourceID><SourceHost>{client}</SourceHost><TargetAddress>mp:MP_PolicyManager</TargetAddress><TargetEndpoint>MP_PolicyManager</TargetEndpoint><TargetHost>{sccmserver}</TargetHost><Timeout>60000</Timeout></Msg>"""
POLICY_REQUEST_TEMPLATE = """<RequestAssignments SchemaVersion="1.00" ACK="false" RequestType="Always"><Identification><Machine><ClientID>GUID:{clientid}</ClientID><FQDN>{clientfqdn}</FQDN><NetBIOSName>{client}</NetBIOSName><SID /></Machine><User /></Identification><PolicySource>SMS:PRI</PolicySource><Resource ResourceType="Machine" /><ServerCookie /></RequestAssignments>"""
REPORT_BODY = """<Report><ReportHeader><Identification><Machine><ClientInstalled>0</ClientInstalled><ClientType>1</ClientType><ClientID>GUID:{clientid}</ClientID><ClientVersion>5.00.8325.0000</ClientVersion><NetBIOSName>{client}</NetBIOSName><CodePage>850</CodePage><SystemDefaultLCID>2057</SystemDefaultLCID><Priority /></Machine></Identification><ReportDetails><ReportContent>Inventory Data</ReportContent><ReportType>Full</ReportType><Date>{date}</Date><Version>1.0</Version><Format>1.1</Format></ReportDetails><InventoryAction ActionType="Predefined"><InventoryActionID>{{00000000-0000-0000-0000-000000000003}}</InventoryActionID><Description>Discovery</Description><InventoryActionLastUpdateTime>{date}</InventoryActionLastUpdateTime></InventoryAction></ReportHeader><ReportBody /></Report>"""

def encode_UTF16_strip_BOM(data):
    return data.encode('utf-16')[2:]

def create_private_key():
    privatekey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return privatekey

def create_certificate(privatekey):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "ConfigMgr Client"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        privatekey.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow() - timedelta(days=2)
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.KeyUsage(digital_signature=True, key_encipherment=False, key_cert_sign=False,
                                key_agreement=False, content_commitment=False, data_encipherment=True,
                                crl_sign=False, encipher_only=False, decipher_only=False),
        critical=False,
    ).add_extension(
        x509.ExtendedKeyUsage([ObjectIdentifier("1.3.6.1.4.1.311.101.2"), ObjectIdentifier("1.3.6.1.4.1.311.101")]),
        critical=False,
    ).sign(privatekey, hashes.SHA256())

    return cert

def SCCM_sign(private_key, data):
        signature = private_key.sign(data, PKCS1v15(), hashes.SHA256())
        signature_rev = bytearray(signature)
        signature_rev.reverse()
        return bytes(signature_rev)
    
def build_MS_public_key_blob(private_key):
    blobHeader = b"\x06\x02\x00\x00\x00\xA4\x00\x00\x52\x53\x41\x31\x00\x08\x00\x00\x01\x00\x01\x00"
    blob = blobHeader + private_key.public_key().public_numbers().n.to_bytes(int(private_key.key_size / 8), byteorder="little")
    return blob.hex().upper()

# taken from https://github.com/synacktiv/SCCMSecrets/blob/master/policies_dumper.py

def generate_registration_request_payload(management_point, machine_name, outcert, outkey):
    private_key = create_private_key()
    certificate = create_certificate(private_key)
    public_key = certificate.public_bytes(serialization.Encoding.DER).hex().upper()
    with open(outcert, 'wb') as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    with open(outkey, 'wb') as f:
        f.write(private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))

    registrationRequest = REGISTRATION_REQUEST_TEMPLATE.format(
        date=datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        encryption=public_key,
        signature=public_key,
        client=machine_name.split('.')[0],
        clientfqdn=machine_name
    )

    signature = SCCM_sign(private_key, encode_UTF16_strip_BOM(registrationRequest)).hex().upper()
    registrationRequestWrapper = REGISTRATION_REQUEST_WRAPPER_TEMPLATE.format(
    data=registrationRequest,
    signature=signature
    )
    registrationRequestWrapper = encode_UTF16_strip_BOM(registrationRequestWrapper) + "\r\n".encode('ascii')

    registrationRequestHeader = SCCM_HEADER_TEMPLATE.format(
        bodylength=len(registrationRequestWrapper)-2,
        client=machine_name,
        date=datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        sccmserver=management_point
    )

    final_body = "--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: text/plain; charset=UTF-16\r\n\r\n".encode('ascii')
    final_body += registrationRequestHeader.encode('utf-16') + "\r\n--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: application/octet-stream\r\n\r\n".encode('ascii')
    final_body += zlib.compress(registrationRequestWrapper) + "\r\n--aAbBcCdDv1234567890VxXyYzZ--".encode('ascii')

    return final_body

def main(args):
    management_point = args.mp_server
    machine_name = args.computer_name
    machine_pass = args.computer_pass
    outcert = f"{machine_name.replace('$', '')}_cert.pem"
    outkey = f"{machine_name.replace('$', '')}_key.pem"
    registration_request_payload = generate_registration_request_payload(management_point, machine_name, outcert, outkey)

    additional_headers = {
        "Connection": "close",
        "Content-Type": "multipart/mixed; boundary=\"aAbBcCdDv1234567890VxXyYzZ\""
    }
    session = requests.Session()
    session.headers.update(MP_INTERACTIONS_HEADERS)
    session.auth = HttpNtlmAuth(machine_name, machine_pass)
    try:
        r = session.request("CCM_POST", f"http://{management_point}/ccm_system_windowsauth/request", headers={**session.headers, **additional_headers}, data=registration_request_payload)
        multipart_data = decoder.MultipartDecoder.from_response(r)
        for part in multipart_data.parts:
            if part.headers[b'content-type'] == b'application/octet-stream':
                xml = zlib.decompress(part.content).decode('utf-16')
            
        root = ET.fromstring(xml[:-1])
        smsid = root.attrib.get('SMSID')
        print(f"[+] successfully registered {machine_name} (SMSID: {smsid})")
        print(f"[+] cert: {outcert} / key: {outkey}")
    except Exception as e:
        print(e)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="register device to SCCM")
    parser.add_argument("--mp-server", required=True, help="SCCM MP server hostname (e.g. sccm-mp.contoso.local)")
    parser.add_argument("--computer-name", required=True, help="computer name (ex. computer01$)")
    parser.add_argument("--computer-pass", required=True, help="computer passsword")

    args = parser.parse_args()
    main(args)