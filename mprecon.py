import argparse
import uuid
import zlib
import requests
from datetime import datetime, timezone
from xml.etree import ElementTree as ET
from requests_toolbelt.multipart import decoder

# reference: https://github.com/synacktiv/SCCMSecrets
from cryptography.hazmat.primitives                     import serialization
from cryptography.hazmat.primitives                     import hashes
from cryptography.hazmat.primitives.asymmetric.padding  import PKCS1v15

def SCCM_sign(private_key, data):
        signature = private_key.sign(data, PKCS1v15(), hashes.SHA256())
        signature_rev = bytearray(signature)
        signature_rev.reverse()
        return bytes(signature_rev)

def load_key(path):
    with open(path, 'rb') as f:
       key_data = f.read()
    private_key = serialization.load_pem_private_key(key_data, password=None)
    return private_key

class MPRecon:
    boundary = "aAbBcCdDv1234567890VxXyYzZ"
    headers = {
        "Content-Type": f'multipart/mixed; boundary="{boundary}"',
    }
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    hostname = "DUMMY-PC"

    def __init__(self, mp_server, verbose):
        self.mp_server = mp_server
        self.verbose = verbose

    def debug_xmlprint(self, xml):
        if self.verbose:
            print("[*] received XML response:")
            ET.indent(xml)
            print(ET.tostring(xml, encoding="unicode"))

    def create_multipart(self, header, body, is_compressed=False):
        body = body.encode('utf-16le')
        data = f"--{self.boundary}\r\ncontent-type: text/plain; charset=UTF-16\r\n\r\n".encode() + header.encode("utf-16") + b"\r\n"
        if is_compressed:
            data+= f"--{self.boundary}\r\ncontent-type: application/octet-stream\r\n\r\n".encode() + zlib.compress(body) + b"\r\n"            
        else:
            data+= f"--{self.boundary}\r\ncontent-type: text/plain; charset=UTF-16\r\n\r\n".encode() + body + b"\x00\x00"+ b"\r\n"
        data+= f"--{self.boundary}--\r\n".encode()
        return data

    def extract_compressed_reply(self, response):
        multipart_data = decoder.MultipartDecoder.from_response(response)
        for part in multipart_data.parts:
            if part.headers[b'content-type'] == b'application/octet-stream':
                return zlib.decompress(part.content).decode('utf-16')

    def search_dp(self, args):
        uid = uuid.uuid4()
        url = f"http://{self.mp_server}/ccm_system/request"
        site_code = args.site_code
        domain = args.domain
        source_ip = args.source_ip
        subnet_address = args.subnet_address
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        body = f'''<ContentLocationRequest SchemaVersion="1.00"  BGRVersion="1">
  <AssignedSite SiteCode="{site_code}"/>
  <ClientPackage RequestForLatest="0" DeploymentFlags="4098"/>
  <ClientLocationInfo LocationType="SMSPACKAGE" DistributeOnDemand="0" UseProtected="0" AllowCaching="0" BranchDPFlags="0" AllowHTTP="1" AllowSMB="0" AllowMulticast="0" UseAzure="1" DPTokenAuth="1" UseInternetDP="0">
    <ADSite Name="Default-First-Site-Name"/>
    <Forest Name="{domain}"/>
    <Domain Name="{domain}"/>
<IPAddresses><IPAddress SubnetAddress="{subnet_address}" Address="{source_ip}"/></IPAddresses><Adapters><Adapter Name="イーサネット" IfType="6" PhysicalAddressExists="1" DnsSuffix="" Description="Microsoft Hyper-V Network Adapter" /></Adapters>  </ClientLocationInfo>
</ContentLocationRequest>\x00'''

        body = body.replace("\n", "\r\n")

        header = f'<Msg SchemaVersion="1.1"><ID>{uid}</ID><SourceID></SourceID><SourceHost>{self.hostname}</SourceHost><TargetAddress>mp:[http]MP_LocationManager</TargetAddress><ReplyTo>direct:{self.hostname}:LS_ReplyLocations</ReplyTo><Priority>3</Priority><Timeout>600</Timeout><ReqVersion>5931</ReqVersion><TargetHost>{self.mp_server}</TargetHost><TargetEndpoint>MP_LocationManager</TargetEndpoint><ReplyMode>Sync</ReplyMode><Protocol>http</Protocol><SentTime>{now}</SentTime><Body Type="ByteRange" Offset="0" Length="{len(body)*2}"/><Hooks/><Payload Type="inline"/></Msg>'

        data = self.create_multipart(header, body)

        print(f"[*] sending request to {self.mp_server}...")
        try:
            response = requests.request("CCM_POST", url, headers=self.headers, data=data)
            reply = self.extract_compressed_reply(response)
            root = ET.fromstring(reply[:-1])
            self.debug_xmlprint(root)
            server_names = root.findall(".//ServerRemoteName")
            print("[+] succeded to locate distribution points")
            for server_name in server_names:
                print(server_name.text)
        except Exception as e:
            print(f"[-] locating distribution points failed. maybe invalid arguments:\n{e}")

    def request_siteinfo(self, args):
        uid = uuid.uuid4()
        url = f"http://{self.mp_server}/ccm_system/request"
        site_code = args.site_code

        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        body = f'''<SiteInformationRequest SchemaVersion="1.00"><SiteCode Name="{site_code}"/></SiteInformationRequest>\x00'''
        
        header = f'''
        <Msg SchemaVersion="1.1">
        <ID>{{{uid}}}</ID><SourceID></SourceID><SourceHost>{self.hostname}</SourceHost>
        <TargetAddress>raw:httpsync:{self.mp_server}:MP_LocationManager</TargetAddress>
        <ReplyTo>direct:{self.hostname}:LS_ReplyLocations</ReplyTo>
        <CorrelationID>{{{uid}}}</CorrelationID>
        <ReplyCapabilities><AllowRegistrationReset>direct:{self.hostname}:ClientRegistration</AllowRegistrationReset></ReplyCapabilities><TargetHost>{self.mp_server}</TargetHost><TargetEndpoint>MP_LocationManager</TargetEndpoint><ReplyMode>Sync</ReplyMode><Protocol>http</Protocol><SentTime>{now}</SentTime><Body Type="ByteRange" Offset="0" Length="{len(body)*2}"/><Hooks><Hook3 Name="zlib-compress"/></Hooks><Payload Type="inline"/>
        </Msg>
        '''

        data = self.create_multipart(header, body, True)

        print(f"[*] request site information to {self.mp_server}...")
        try:
            response = requests.request("CCM_POST", url, headers=self.headers, data=data)
            reply = self.extract_compressed_reply(response)
            root = ET.fromstring(reply.encode()[:-1].decode())
            self.debug_xmlprint(root)
            site_elem = root.find('.//Site')
            site_code = site_elem.findtext('SiteCode')
            version = site_elem.findtext('Version')
            build_number = site_elem.findtext('BuildNumber')

            print(f"[+] site information:")
            print("- SiteCode:", site_code)
            print("- Version:", version)
            print("- BuildNumber:", build_number)
        except Exception as e:
            print(f"[-] locating mp points failed. maybe invalid arguments:\n{e}")

    def list_mp(self, args):
        url = f"http://{self.mp_server}/SMS_MP/.sms_aut?MPLIST"

        try:
            print(f"[*] Querying to {url}...")
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            root = ET.fromstring(response.text)
            self.debug_xmlprint(root)
            print("[+] succeded to list management points")
            for mp in root.findall(".//MP"):
                name = mp.get("Name")
                version_elem = mp.find("Version")
                version = version_elem.text if version_elem is not None else "N/A"
                print(f"{name} (buld number: {version})")

        except Exception as e:
            print(f"[-] Failed to fetch MP list: {e}")

    def get_primary_user(self, args):
        smsid = args.smsid
        url = f"http://{self.mp_server}/SMS_MP/.sms_aut?GETCLIENTAFFINITY&{smsid}"
        print("[*] querying primary user for " + smsid)
        try:
            response = requests.get(url, timeout=10)
            root = ET.fromstring(response.text)
            user = root.find('.//User')
            print(f'[+] primary user for {smsid}\'s device found: {user.text}')
        except Exception as e:
            print(f"[-] Failed to query primary user info: {e}")

    def client_lookup(self, args):
        uid = uuid.uuid4()
        url = f"http://{self.mp_server}/ccm_system/request"
        site_code = args.site_code
        clientid = args.smsid
        private_key = load_key(args.device_key)
        
        body = f'<ClientIDRequest><Identification><Machine><SMBIOS>FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF</SMBIOS><MacAddress>{args.mac_address}</MacAddress></Machine></Identification></ClientIDRequest>\x00'
        payload = body.encode('utf-16le')
        payload_signature = SCCM_sign(private_key, zlib.compress(payload)).hex().upper()

        header =f'''
        <Msg SchemaVersion="1.1">
        <ID>{{{uid}}}</ID>
        <SourceID>{clientid}</SourceID>
        <SourceHost>{self.hostname}</SourceHost>
        <TargetAddress>mp:[http]MP_ClientIdManager</TargetAddress>
        <ReplyTo>direct:dummy:dummy</ReplyTo>
        <ReplyCapabilities><AllowRegistrationReset>direct:{self.hostname}:ClientRegistration</AllowRegistrationReset></ReplyCapabilities><TargetHost>{self.mp_server}</TargetHost><TargetEndpoint>MP_ClientIdManager</TargetEndpoint><ReplyMode>Sync</ReplyMode><Protocol>http</Protocol><SentTime>{self.now}</SentTime><Body Type="ByteRange" Offset="0" Length="{len(payload)}"/><Hooks>
        <Hook3 Name="zlib-compress"/><Hook2 Name="clientauth"><Property Name="AuthSenderMachine">{self.hostname}</Property><Property Name="HashAlgorithm">1.2.840.113549.1.1.11</Property><Property Name="ClientCapability">NonSSL</Property><Property Name="PayloadSignature">{payload_signature}</Property></Hook2></Hooks><Payload Type="inline"/></Msg>
        '''

        data = self.create_multipart(header, body, True)
        print(f"[*] sending request to {self.mp_server}...")
        try:
            response = requests.request("CCM_POST", url, headers=self.headers, data=data)
            reply = self.extract_compressed_reply(response)
            root = ET.fromstring(reply.encode()[:-1].decode())
            self.debug_xmlprint(root)
            clientid = root.find('.//ClientID').text
            netbios_name = root.find('.//NetbiosName').text

            print("[+] client lookup success!")
            print(f"- NetbiosName: {netbios_name}")
            print(f"- ClientID: {clientid}")
        except Exception as e:
            print(f"[-] client lookup failed. maybe invalid arguments")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Collect information from management point server")
    parser.add_argument('-v', '--verbose', action='store_true', help='show information for debugging')    
    
    subparsers = parser.add_subparsers(dest='command', description='commands')
    search_dp_parser = subparsers.add_parser('search_dp', help='search distribution points')
    search_dp_parser.add_argument("--mp-server", required=True, help="SCCM MP server hostname (e.g. sccm-mp.contoso.local)")
    search_dp_parser.add_argument("--site-code", required=True, help="SCCM Site code (e.g. MCM)")
    search_dp_parser.add_argument("--domain", required=True, help="Domain name (e.g. contoso.local)")
    search_dp_parser.add_argument("--source-ip", default="192.168.0.10", help="Source IP address of a fake device")
    search_dp_parser.add_argument("--subnet-address", default="192.168.0.0", help="Subnet address of a fake device")

    list_mp_parser = subparsers.add_parser('list_mp', help='list management points and their build numbers')
    list_mp_parser.add_argument("--mp-server", required=True, help="SCCM MP server hostname (e.g. sccm-mp.contoso.local)")

    get_primary_user_parser = subparsers.add_parser('get_primary_user', help='retrieve primary user information via the target device\'s SMSID')
    get_primary_user_parser.add_argument("--mp-server", required=True, help="SCCM MP server hostname (e.g. sccm-mp.contoso.local)")
    get_primary_user_parser.add_argument("--smsid", required=True, help="target device's SMSID")

    request_siteinfo_parser = subparsers.add_parser('request_siteinfo', help='request site info')
    request_siteinfo_parser.add_argument("--mp-server", required=True, help="SCCM MP server hostname (e.g. sccm-mp.contoso.local)")
    request_siteinfo_parser.add_argument("--site-code", required=True, help="SCCM Site code (e.g. MCM)")

    client_lookup_parser = subparsers.add_parser('client_lookup', help='query SMSID via device\'s mac address')
    client_lookup_parser.add_argument("--mp-server", required=True, help="MP server hostname (e.g. sccm-mp.contoso.local)")
    client_lookup_parser.add_argument("--site-code", required=True, help="site code (e.g. MCM)")
    client_lookup_parser.add_argument("--device-key", required=True, help="path to a device's private key (ex. key.pem)")
    client_lookup_parser.add_argument("--smsid", required=True, help="device's SMSID for the provided device's private key (ex. GUID:FD520E65-8D0D-429F-A0A3-C08A66DAB5BA)")
    client_lookup_parser.add_argument("--mac-address", required=True, help="MAC address to query device's guid")

    args = parser.parse_args()
    mprecon = MPRecon(args.mp_server, args.verbose)
    if args.command == 'search_dp':
        mprecon.search_dp(args)
    elif args.command == 'list_mp':
        mprecon.list_mp(args)
    elif args.command == 'get_primary_user':
        mprecon.get_primary_user(args)
    elif args.command == 'request_siteinfo':
        mprecon.request_siteinfo(args)
    elif args.command == 'client_lookup':
        mprecon.client_lookup(args)
    else:
        print("[-] unknown command")