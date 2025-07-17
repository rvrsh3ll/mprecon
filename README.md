# mprecon

It is just a small script to collect various information from a management point server, which I created while learning SCCM.
The following is the information currently retrieved from a management point server.

- distribution point server location
- management point server location
- device's NetBiosName and SMSID (ClientID)
- primary user information
- site information (version, build number etc..)

```
$ python3 mprecon.py -h
usage: mprecon.py [-h] [-v] {search_dp,list_mp,get_primary_user,request_siteinfo,client_lookup} ...

Collect information from management point server

options:
  -h, --help            show this help message and exit
  -v, --verbose         show information for debugging

subcommands:
  commands

  {search_dp,list_mp,get_primary_user,request_siteinfo,client_lookup}
    search_dp           search distribution points
    list_mp             list management points and their build numbers
    get_primary_user    retrieve primary user information via the target device's SMSID
    request_siteinfo    request site info
    client_lookup       query SMSID via device's mac address
```

I've only tested this in my lab so it might not work depending on SCCM configurations. I will fix any issues when I need to.

## Usage

### Locate distribution points

mprecon can query a management point server to get the locations of distribution point (DP) servers.

```
$ python3 mprecon.py search_dp --mp-server SCCM-MP.contoso.local --domain contoso.local --site-code MCM
[*] sending request to SCCM-MP.contoso.local...
[+] succeded to locate distribution points
SCCM-DP.contoso.local
```

### List management points

mprecon can also ask a management point server to list management points.

```
$ python3 mprecon.py list_mp --mp-server sccm-mp.contoso.local
[*] Querying to http://sccm-mp.contoso.local/SMS_MP/.sms_aut?MPLIST...
[+] succeded to list management points
SCCM-MP.contoso.LOCAL (buld number: 9128)
```

### Lookup SMSID (ClientID)

Even a device's SMSID can be retrieved from a management point server.

To achieve this, device authentication is required. Therefore, you first need to register a fake device in SCCM using your preferred tool.

The example below uses a small script based entirely on the excellent tool  SCCMSecrets (https://github.com/synacktiv/SCCMSecrets) by Synacktiv.

```
$ python3 register_client.py --mp-server sccm-mp.contoso.local --computer-name test$ --computer-pass *******
[+] successfully registered test$ (SMSID: GUID:FD520E65-8D0D-429F-A0A3-C08A66DAB5BA)
[+] cert: test_cert.pem / key: test_key.pem
```

Once you have the fake device's key and SMSID, you can use the client_lookup command to retrieve the target device's SMSID via its MAC address.

```
$ python3 mprecon.py client_lookup --mp-server SCCM-MP.contoso.local --site-code MCM --device-key test_key.pem --smsid GUID:FD520E65-8D0D-429F-A0A3-C08A66DAB5BA --mac-address  00:15:5d:29:af:2d
[*] sending request to SCCM-MP.contoso.local...
[+] client lookup success!
- NetbiosName: SCCM-CLIENT
- ClientID: GUID:4413D802-A3DF-47D0-A680-D598202C5167
```

This SMSID can then be used with the get_primary_user command.

### Get primary user information

A primary user information of a device can be queried via the device's SMSID.

```
$ python3 mprecon.py get_primary_user --mp-server SCCM-MP.contoso.local --smsid 'GUID:4413D802-A3DF-47D0-A680-D598202C5167'
[*] querying primary user for GUID:4413D802-A3DF-47D0-A680-D598202C5167
[+] primary user for GUID:4413D802-A3DF-47D0-A680-D598202C5167's device found: contoso\testuser
```

### Request site information

mprecon can retrieves site information from a management point server.

```
$ python3 mprecon.py request_siteinfo --mp-server SCCM-MP.contoso.local --site-code MCM
[*] request site information to SCCM-MP.contoso.local...
[+] site information:
- SiteCode: MCM
- Version: 5.00.9128.1000
- BuildNumber: 9128
```

More detailed information can be received with `-v` option.

## Reference

- https://github.com/synacktiv/SCCMSecrets
- https://github.com/subat0mik/Misconfiguration-Manager
- https://github.com/slygoo/pssrecon
- https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/
- https://www.synacktiv.com/advisories/microsoft-configuration-manager-configmgr-2403-unauthenticated-sql-injections