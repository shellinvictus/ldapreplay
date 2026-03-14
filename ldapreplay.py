#!/usr/bin/env python3

import os
import json
import binascii
import tempfile
import argparse
from colorama import init as colorama_init
from colorama import Back, Fore, Style
from dnslib import RR,QTYPE,RCODE
from dnslib.zoneresolver import ZoneResolver
from dnslib.server import DNSServer
from twisted.internet import reactor, endpoints
from twisted.internet.protocol import Factory
from ldaptor import ldapfilter, inmemory
from ldaptor.protocols import pureldap
from ldaptor.protocols.pureber import BEROctetString
from ldaptor.protocols.ldap import ldapserver, ldaperrors
from ldaptor.protocols.ldap.ldapsyntax import LDAPEntry
from ldaptor.protocols.ldap.distinguishedname import DistinguishedName
from ldap3.protocol.schemas.ad2012R2 import ad_2012_r2_schema
from ldaptor.entryhelpers import MatchMixin

if 'PATCHED' not in dir(MatchMixin):
    print('[-] you need to patch ldaptor! Check the README')
    exit(0)

# otherwise it fails with bloodhound-python
ldapserver.pureldap.LDAPBERDecoderContext_LDAPBindRequest.Identities[0x89] = BEROctetString

FLAG_CR_NTDS_NC      = 0x00000001
FLAG_CR_NTDS_DOMAIN  = 0x00000002
DOMAIN = FLAG_CR_NTDS_NC | FLAG_CR_NTDS_DOMAIN

OID_PAGING = b'1.2.840.113556.1.4.319' # TODO: unsupported
OID_SDFLAG = b'1.2.840.113556.1.4.801'
OID_SEARCH = b'1.2.840.113556.1.4.473'

LDAP_SCOPE_BASE = 0
LDAP_SCOPE_ONELEVEL = 1
LDAP_SCOPE_SUBTREE = 2

HEXA_ATTRIBUTES = {
    # sid
    'objectsid',
    # guid
    'objectguid',
    'schemaidguid',
    'currentValue',
    'msfve-recoveryguid',
    'msfve-volumeguid',
    'ms-ds-consistencyguid',
    # others
    'supplementalcredentials',
    'ntsecuritydescriptor',
    'replpropertymetadata',
    'msds-allowedtoactonbehalfofotheridentity',
}

DNS_ZONE = """
$TTL 3600 ; Default TTL is 24 hours
$ORIGIN {fqdn}.

@    IN  SOA  dc.{fqdn}. hostmaster.{fqdn}. (
        2026010101
        3600
        600
        86400
        3600 )

@    IN  NS   dc.{fqdn}.
dc   IN  A    127.0.0.1

_ldap._tcp.dc._msdcs        IN SRV 0 100 3890 dc.{fqdn}.
_ldap._tcp.pdc._msdcs       IN SRV 0 100 3890 dc.{fqdn}.
_ldap._tcp.gc._msdcs        IN SRV 0 100 3268 dc.{fqdn}.
"""


def convert_to_tuples(items):
    return [(k, v) for k, v in items.items()]


class NTDSBackend:
    def __init__(self, path):
        self.dn = {}
        self.sid = {}
        self.dn_level = {}
        self.fqdn = None
        self.real_attribute_names = {}
        self.ncname_to_dn = {}
        self.buildRootDse(path)
        self.load_json(f'{path}/user.json')
        self.load_json(f'{path}/group.json')
        self.load_json(f'{path}/computer.json')
        self.load_json(f'{path}/organizationalUnit.json')
        self.load_json(f'{path}/container.json')
        self.load_json(f'{path}/groupPolicyContainer.json')
        self.load_json(f'{path}/msDS-GroupManagedServiceAccount.json')
        self.load_json(f'{path}/domainPolicy.json')
        self.load_json(f'{path}/attributeSchema.json')
        self.load_json(f'{path}/classSchema.json')

    def normalize_attributes(self, attrs):
        '''
        - Transform values of a dict into lists, each sub value must be a bytes
        - Get the raw value if the attribute name starts with RAW_, it requires
          a patch of ntdissector. Raw attributes could be dates, raw bytes,
          some integers, ...
        - Some attributes are also stored in hexa
        '''
        normalized = {}
        for k, v in attrs.items():
            if v is None or f'RAW_{k}' in attrs:
                continue
            if k.startswith('RAW_'):
                k = k[4:]
            low = k.lower()
            self.real_attribute_names[low] = k
            k = low
            if k in HEXA_ATTRIBUTES:
                normalized[k] = [binascii.unhexlify(v)]
                continue
            if isinstance(v, list):
                normalized[k] = [str(v2).encode() for v2 in v]
            elif isinstance(v, int):
                normalized[k] = [str(v).encode()]
            else:
                normalized[k] = [v.encode()]
        return normalized

    def save_obj(self, o):
        dn = o['distinguishedName'].lower()
        o['dn'] = dn
        # We need to transform the DN into a simple name to support the
        # query (objectCategory=XXXX)
        cat = o['objectCategory']
        if cat.startswith('CN=Computer'):
            o['objectCategory'] = 'computer'
        elif cat.startswith('CN=Person'):
            o['objectCategory'] = 'person'
        elif cat.startswith('CN=Organizational-Unit'):
            o['objectCategory'] = 'organizationalUnit'
        elif cat.startswith('CN=Group-Policy-Container'):
            o['objectCategory'] = 'groupPolicyContainer'
        elif cat.startswith('CN=Container'):
            o['objectCategory'] = 'container'
        norm = self.normalize_attributes(o)
        self.dn[dn] = norm
        self.dn_level[dn] = len(dn.split(','))
        # indexed SIDs
        if 'objectsid' in norm:
            self.sid[norm['objectsid'][0]] = norm

    def load_json(self, filename):
        log(f'[+] parsing {filename}')
        with open(filename) as f:
            for line in f:
                self.save_obj(json.loads(line))

    def add_ncname(self, o):
        '''
        NCName are unique integers to identify an object, this is an
        equivalent of the DN. We need to resolve the value into its
        equivalent DN.
        '''
        if 'subRefs' not in o:
            return
        if isinstance(o['subRefs'], list):
            for x in o['subRefs']:
                self.ncname_to_dn[x] = o['distinguishedName']
        else:
            self.ncname_to_dn[o['subRefs']] = o['distinguishedName']

    def generate_attribute_types(self):
        '''
        ldap3 has already a dataset for AD 2012. We need to set at least
        a part of the schema to set the correct type on attriutes.
        This would be sufficient for most of the tools.
        '''
        types = json.loads(ad_2012_r2_schema)['raw']['attributeTypes']
        # Fix missing attributes and required by bloodhound
        types.append("( 1.2.840.113556.1.8000.2554.50051.45980.28112.18903.35903.6685103.1224907.2.2 NAME 'ms-Mcs-AdmPwdExpirationTime' SYNTAX '1.2.840.113556.1.4.906' SINGLE-VALUE )")
        types.append("( 1.2.840.113556.1.6.44.1.1 NAME 'msLAPS-PasswordExpirationTime' SYNTAX '1.2.840.113556.1.4.906' SINGLE-VALUE )")
        return types

    def buildRootDse(self, path):
        self.root_dse = {
            'defaultNamingContext': [],
            'rootDomainNamingContext': [],
            'namingContexts': [],
            'configurationNamingContext': [],
            'schemaNamingContext': [],
            'supportedLDAPVersion': ['3'],
            'supportedControl': [
                # OID_PAGING.decode(),
                OID_SDFLAG.decode(),
                OID_SEARCH.decode(),
            ],
            'subschemaSubentry': [],
        }

        # namingContexts
        shorter = None
        with open(f'{path}/domainDNS.json') as f:
            for line in f:
                o = json.loads(line)
                dn = o['distinguishedName']
                self.add_ncname(o)
                self.root_dse['namingContexts'].append(dn)
                if shorter is None:
                    shorter = o
                elif len(dn) < len(shorter['distinguishedName']):
                    shorter = o

        # defaultNamingContext (domain child of the forest)
        self.root_dse['defaultNamingContext'].append(shorter['distinguishedName'])

        # It fails if we register all domainDNS (ForestDnsZones + DomainDnsZones) which
        # don't have the attribute 'objectSid'
        # so save only the main
        self.save_obj(shorter)

        # configurationNamingContext
        with open(f'{path}/configuration.json') as f:
            for line in f:
                o = json.loads(line)
                self.add_ncname(o)
                self.save_obj(o)
                dn = o['distinguishedName']
                self.root_dse['configurationNamingContext'].append(dn)

        # rootDomainNamingContext (root of the forest)
        with open(f'{path}/crossRef.json') as f:
            for line in f:
                o = json.loads(line)
                dn = o['distinguishedName']
                is_domain = (o['systemFlags'] & DOMAIN) == DOMAIN

                if is_domain:
                    dn = 'DC=' + ',DC='.join(o['dnsRoot'].split('.'))
                    o['nCName'] = dn
                    self.root_dse['rootDomainNamingContext'].append(dn)
                    self.fqdn = o['dnsRoot']
                    self.root_domain = dn
                # else:
                    # resolve dn (required for bloodhound-python)
                    # o['nCName'] = self.ncname_to_dn.get(o['nCName'], '')

                # a partition but not a domain
                # elif o['systemFlags'] == FLAG_CR_NTDS_NC:
                    # if 'Schema' in dn:
                        # self.root_dse['schemaNamingContext'].append(dn)
                        # print(dn)
                    # else:
                        # self.root_dse['configurationNamingContext'].append(dn)
                # applicative partitions
                # else:
                    # self.root_dse['namingContexts'].append(dn)

                self.save_obj(o)

        # subschemaSubentry
        # ntdissector doesn't store attribute syntaxes, so hard code a schema
        o = {
            'distinguishedName': f'CN=MiniSchema,CN=Schema,CN=Configuration,{self.root_domain}',
            'objectCategory': 'subschema',
            'name': 'MiniSchema',
            'objectClass': ['subschema', 'top'],
            'attributeTypes': self.generate_attribute_types(),
            'dITContentRules': [],
        }
        dn = o['distinguishedName']
        self.save_obj(o)
        self.root_dse['subschemaSubentry'].append(dn)

        # schemaNamingContext
        with open(f'{path}/dMD.json') as f:
            for line in f:
                o = json.loads(line)
                self.save_obj(o)
                dn = o['distinguishedName']
                self.root_dse['schemaNamingContext'].append(dn)
                self.root_dse['namingContexts'].append(dn)

        self.root_dse = convert_to_tuples(self.normalize_attributes(self.root_dse))


class JSONLDAPServer(ldapserver.LDAPServer):
    def __init__(self, backend):
        super().__init__()
        self.backend = backend

    def __rootDSE(self, reply):
        entry = pureldap.LDAPSearchResultEntry(
            objectName='',
            attributes=self.backend.root_dse,
        )
        reply(entry)
        return pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode)

    def handle_LDAPSearchRequest(self, request, controls, reply):
        def scope_allows(dn):
            if scope == LDAP_SCOPE_BASE:
                return dn == base_dn
            elif scope == LDAP_SCOPE_ONELEVEL:
                if not dn.endswith(base_dn_compare):
                    return False
                diff = self.backend.dn_level[dn] - base_dn_level
                return diff == 1
            elif scope == LDAP_SCOPE_SUBTREE:
                return not base_dn or dn == base_dn or dn.endswith(base_dn_compare)

        def process_entry(dn, attrs):
            '''
            Manage filtering, scope and attributes selection.
            Each keys of attrs are in lower case.
            '''
            if base_dn and not (dn == base_dn or dn.endswith(base_dn_compare)):
                return
            if not scope_allows(dn):
                return

            entry = inmemory.ReadOnlyInMemoryLDAPEntry(
                dn=DistinguishedName(dn),
                attributes=attrs)

            if entry.match(request.filter):
                if has_wildcard or has_plus:
                    a = {
                        self.backend.real_attribute_names[k]: v
                        for k, v in attrs.items()
                    }
                    if not has_sd and 'ntsecuritydescriptor' in attrs:
                        del a['nTSecurityDescriptor']

                elif has_11:
                    a = {}

                elif req_attrs:
                    a = {
                        self.backend.real_attribute_names[k]: attrs[k]
                        for k in req_attrs if k in attrs
                    }
                    if has_sd:
                        if 'ntsecuritydescriptor' in attrs:
                            a['nTSecurityDescriptor'] = attrs['ntsecuritydescriptor']
                        else:
                            a['nTSecurityDescriptor'] = []

                entry = pureldap.LDAPSearchResultEntry(
                    objectName=dn,
                    attributes=convert_to_tuples(a))
                reply(entry)

        base_dn = request.baseObject.lower().decode()
        base_dn_compare = ',' + base_dn
        base_dn_level = len(base_dn.split(','))
        scope = request.scope
        req_attrs = [k.decode().lower() for k in request.attributes]
        has_plus = '+' in req_attrs # operational attrs, not implemented
        has_wildcard = '*' in req_attrs or not req_attrs # all attrs
        has_11 = '1.1' in req_attrs # none

        # security descriptor
        has_sd = False
        if controls:
            for c in controls:
                if c[0] == OID_SDFLAG:
                    has_sd = True
                    break

        if not base_dn and scope == LDAP_SCOPE_BASE:
            return self.__rootDSE(reply)

        # print(has_sd, request.filter.toWire())

        # optimization for (objectSid=XXXXX)
        query = request.filter.toWire()
        objectsid = b'\xa3)\x04\tobjectsid\x04\x1c'
        if query.lower().startswith(objectsid):
            hex_sid = query[len(objectsid):]
            if hex_sid in self.backend.sid:
                attrs = self.backend.sid[hex_sid]
                dn = attrs['distinguishedname'][0].decode().lower()
                process_entry(dn, attrs)
        else:
            # loop on all objects at each query...
            for dn, attrs in self.backend.dn.items():
                process_entry(dn, attrs)

        return pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode)


class LDAPFactory(Factory):
    def __init__(self, backend):
        self.backend = backend

    def buildProtocol(self, addr):
        return JSONLDAPServer(self.backend)


# Disable all dns logging
class DNSLogger:
    def log_prefix(self, handler):
        pass
    def log_recv(self, handler, data):
        pass
    def log_send(self,handler, data):
        pass
    def log_request(self, handler, request):
        pass
    def log_reply(self, handler, reply):
        pass
    def log_truncated(self, handler, reply):
        pass
    def log_error(self, handler, e):
        pass
    def log_data(self, dnsobj):
        pass

def log(s, color=Fore.YELLOW):
    print(f'{color}{s}{Fore.RESET}')


if __name__ == '__main__':
    colorama_init()

    parser = argparse.ArgumentParser()
    parser.add_argument('path', metavar='NTDISSECTOR_OUTPUT_PATH')
    args = parser.parse_args()

    backend = NTDSBackend(args.path)

    log(f'[+] detected domain: {backend.fqdn}')

    log(f'[+] running dns server on :5353 (udp)')
    fp = tempfile.NamedTemporaryFile(delete_on_close=False)
    fp.write(DNS_ZONE.format(fqdn=backend.fqdn).encode())
    fp.close()
    resolver = ZoneResolver(open(fp.name), False)
    udp_server = DNSServer(resolver, port=5353, logger=DNSLogger())
    udp_server.start_thread()
    os.unlink(fp.name)

    log(f'[+] running ldap server on :3890')
    log(f'[+] running gc server on :3268')

    print()
    print('Some examples below:')

    print()
    log('# ldapsearch', Fore.BLUE)
    print(f'ldapsearch -x -H ldap://127.0.0.1:3890 -b "{backend.root_domain}"')

    print()
    log('# ldapdomaindump', Fore.BLUE)
    print('ldapdomaindump ldap://127.0.0.1:3890 -at SIMPLE')

    print()
    log('# bloodhound-python', Fore.BLUE)
    log('# use the same IP for the first iptables and the parameter -ns!', Fore.BLUE)
    print('sudo iptables -t nat -I OUTPUT -d 127.53.0.1 -p udp --dport 53 -j REDIRECT --to-ports 5353')
    print('sudo iptables -t nat -I OUTPUT -d 127.0.0.1 -p tcp --dport 389 -j REDIRECT --to-ports 3890')
    print(f'bloodhound.py -ns 127.53.0.1 -d {backend.fqdn} -c DCOnly -u whatever -p whatever --auth-method ntlm --disable-pooling')
    print()

    factory = LDAPFactory(backend)
    endpoint = endpoints.TCP4ServerEndpoint(reactor, 3890)
    endpoint.listen(factory)
    reactor.listenTCP(3268, factory)
    reactor.run()
