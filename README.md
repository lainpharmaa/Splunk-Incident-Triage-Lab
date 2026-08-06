Incident Case: BOTSv1 Web Compromise & C2 Infrastructure Analysis
Target Organization: Wayne Enterprises (imreallynotbatman.com)
Analyst: Prince Bhattarai
Date: July 2026
Framework: Lockheed Martin Cyber Kill Chain / NIST SP 800-61

## Executive Summary

On August 10, 2016, internal monitoring systems detected a successful web defacement attack targeting Wayne Enterprises' public web application (www.imreallynotbatman.com).

Subsequent forensic investigation into enterprise SIEM (Splunk) logs revealed a multi-stage intrusion executed by an external adversary. The threat actor initially conducted automated web vulnerability scans against the Joomla CMS architecture, followed by a brute-force credential stuffing attack against the administrative portal (/joomla/administrator/index.php).

Upon gaining unauthorized administrative access, the adversary uploaded a trojanized binary (3791.exe) disguised as an ApacheBench utility and established outbound Command & Control (C2) communication to download defacement assets (/poisonivy-is-coming-for-you-batman.jpeg). Threat intelligence pivoting across OSINT platforms (VirusTotal, ThreatMiner, Hybrid Analysis) linked the infrastructure to adversary handle Lillian (po1s0n1vy.com), C2 IP 23.22.63.114, and secondary backdoor payload (MirandaTateScreensaver.scr.exe). Immediate containment actions included IP/domain perimeter blocks, credential resets, and endpoint signature deployments.

To systematically track the adversary's footprint across our enterprise environment, this investigation maps log evidence against the Lockheed Martin Cyber Kill Chain framework. Logs were analyzed using Splunk Enterprise across web stream, intrusion detection (Suricata), firewall (Fortigate UTM), host system (Windows Event Logs), and endpoint threat detection (Sysmon) sources.

Dataset: BOTSv1, public dataset by Splunk — https://github.com/splunk/botsv1 is the source.

## Phase 1: Reconnaissance & Vulnerability Scanning

To begin the investigation, I queried Splunk for all event logs related to our web domain (imreallynotbatman.com) to identify any initial scanning or suspicious activity.

```
index=botsv1 imreallynotbatman.com
```

![Image 1](images/screenshot-01.png)

Next, I filtered by the stream:http sourcetype to inspect web traffic and examined the src_ip field.

```
index=botsv1 imreallynotbatman.com sourcetype=stream:http
```

![Image 2](images/screenshot-02.png)

Looking at the src_ip distribution in the HTTP stream logs, two external IP addresses stood out: 40.80.148.42 (accounting for 93.4% of total requests) and 23.22.63.114 (accounting for 6.6% of total requests). Since IP 40.80.148.42 generated the vast majority of inbound traffic, I checked our Suricata Intrusion Detection System (IDS) logs to see if any security alerts were triggered by this IP address.

```
index="botsv1" imreallynotbatman.com sourcetype="suricata" src_ip="40.80.148.42"
```

![Image 3](images/screenshot-03.png)

This query shows the Suricata logs for the IP address we're investigating. Next I checked the alerts section of Suricata to see what was flagged.

![Image 4](images/screenshot-04.png)

As shown above, the Suricata alert.signature field revealed high-volume alerts for Cross-Site Scripting (XSS), SQL Injection (SQLi), and XML External Entity (XXE) attempts. To confirm what tool generated these alerts, I navigated back to the HTTP stream logs to inspect the User-Agent strings.

```
index=botsv1 imreallynotbatman.com sourcetype="stream:http"
```

![Image 5](images/screenshot-05.png)

Two user-agent strings stood out as red flags: "Python-urllib/2.7" and `;print(md5(acunetix_wvs_security_test));$a=` — the latter references Acunetix, a web vulnerability scanner. This confirmed that the attacker at IP 40.80.148.42 used the Acunetix Web Vulnerability Scanner to automatically probe and map our web application for security flaws prior to launching exploitation attempts.

This sums up Phase 1, Reconnaissance & Vulnerability Scanning.

## Phase 2: Exploitation & Brute-Force Attack

Next I moved to the exploitation phase, to look for potential exploitation attempts against the web server and see whether the attacker succeeded.

First, counting requests by source IP against the webserver:

```
index=botsv1 imreallynotbatman.com sourcetype=stream* | stats count(src_ip) as Requests by src_ip | sort - Requests
```

![Image 6](images/screenshot-06.png)

Narrowing down to requests sent to our web server, which has the IP 192.168.250.70:

```
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70"
```

![Image 7](images/screenshot-07.png)

The src_ip interesting field shows three IPs — one is our local IP, and the other two are remote IPs originating HTTP traffic toward our webserver.

Looking at the http_method field to see what kind of activity the attacker was attempting:

![Image 8](images/screenshot-08.png)

Most requests came through POST, so:

```
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST
```

![Image 9](images/screenshot-09.png)

The src_ip field shows two IP addresses sending all the POST requests to our server.

Navigating to the URI interesting field:

![Image 10](images/screenshot-10.png)

This shows our webserver runs Joomla CMS on the backend. Since the URI contains the login page for the admin portal, I examined incoming traffic to that panel next to check for a potential brute-force attack. After some digging, I confirmed the Joomla admin login portal URL:

https://www.joomla.org/administrator/index.php

![Image 11](images/screenshot-11.png)

Using this:

```
index=botsv1 imreallynotbatman.com sourcetype=stream:http dest_ip="192.168.250.70" uri="/joomla/administrator/index.php"
```

Then I checked the form_data field from the interesting fields, since it shows all requests sent from the admin login page to the server.

![Image 12](images/screenshot-12.png)

Assuming the attacker tried multiple credentials to gain access, I dug deeper:

```
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST uri="/joomla/administrator/index.php" | table _time uri src_ip dest_ip form_data
```

This gives a cleaner view of the events, making it easier to spot differences.

![Image 13](images/screenshot-13.png)

IP 23.22.63.114 was attempting brute forcing, and the time elapsed between events was short — the attacker is probably using an automated tool.

To make tracking easier, I used regex to extract the password values against the passwd field:

```
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST form_data=*username*passwd* | rex field=form_data "passwd=(?<creds>\w+)" | table src_ip creds
```

![Image 14](images/screenshot-14.png)

This extracted the passwords being used against the username "admin" on the webserver's admin panel. Examining the http_user_agent field, we find two distinct values:

![Image 15](images/screenshot-15.png)

The user agent shows the attacker used Python scripting to automate the brute-force attack.

![Image 16](images/screenshot-16.png)

Adding the time field for a clear picture: this result shows a continuous brute-force attempt from IP 23.22.63.114, plus one password attempt ("batman") from IP 40.80.148.42 using a Mozilla browser.

## Phase 3: Installation Phase

Since imreallynotbatman.com was compromised, and the attacker used a Python script to automate finding the correct password, it's reasonable to assume the attacker was setting up backdoors in the system.

To begin, I narrowed down HTTP traffic into our server (192.168.250.70) containing any executables:

```
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" *.exe
```

![Image 17](images/screenshot-17.png)

This found two files: an executable, 3791.exe, and a PHP file, agent.php. I checked for the IP address found earlier to confirm it's the same adversary:

```
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" "part_filename{}"="3791.exe"
```

![Image 18](images/screenshot-18.png)

Confirmed — this is the same IP found earlier, so it's clear the attacker who gained unauthorized access uploaded 3791.exe. I then checked whether the file executed on our system.

![Image 19](images/screenshot-19.png)

Looking at the source field, 3791.exe was executed and appears across:
1. xmlwineventlog
2. wineventlog
3. fortigate_utm

To confirm, I checked the xmlwineventlog event logs directly.

![Image 20](images/screenshot-20.png)

This confirms 3791.exe was executed — the system is compromised.

Next, I pulled the file hash to research the malware.

![Image 21](images/screenshot-21.png)

Using the hash ec78c938d8453739ca2a370b9c275971ec46caf6e479de2b2d04e97cc47fa45d to search VirusTotal:

![Image 22](images/screenshot-22.png)

Confirmed: this binary is a trojanized version of the ApacheBench (ab.exe) utility, used here to establish a backdoor and mask malicious behavior.

## Phase 4: Actions on Objectives & Web Defacement

With the system confirmed compromised and the site defaced, next I identified what caused the defacement — starting with Suricata logs to see what rules were triggered.

```
index=botsv1 dest=192.168.250.70 sourcetype=suricata
```

![Image 23](images/screenshot-23.png)

Since the IPs communicating with the server weren't external, I checked whether any IP from our server was communicating outbound:

```
index=botsv1 src=192.168.250.70 sourcetype=suricata
```

![Image 24](images/screenshot-24.png)

This shows three external IPs our web server was sending outbound traffic to, with a large volume worth investigating further. I pivoted on each IP.

First IP:

```
index=botsv1 src=192.168.250.70 sourcetype=suricata dest_ip=23.22.63.114
```

![Image 25](images/screenshot-25.png)

This shows two PHP files and one JPEG file. The JPEG stood out, so I traced where it came from:

```
index=botsv1 url="/poisonivy-is-coming-for-you-batman.jpeg" dest_ip="192.168.250.70" | table _time src dest_ip http.hostname url
```

![Image 26](images/screenshot-26.png)

This confirms the suspicious file poisonivy-is-coming-for-you-batman.jpeg was downloaded from the attacker's host, prankglassinebracket.jumpingcrab.com, which defaced the site.

I also checked the Fortigate firewall for SQL injection attempts from IP 40.80.148.42:

```
index=botsv1 src_ip="40.80.148.42" sourcetype="fortigate_utm"
```

![Image 27](images/screenshot-27.png)

This shows HTTP.URI.SQL.Injection was the rule triggered during the SQL injection attempt.

Since the domain seen in the logs (rather than a static IP) points to Dynamic DNS use, I searched fortigate_utm further:

```
index=botsv1 sourcetype=fortigate_utm "poisonivy-is-coming-for-you-batman.jpeg"
```

![Image 28](images/screenshot-28.png)

The url field contains the FQDN prankglassinebracket.jumpingcrab.com:1337/poisonivy-is-coming-for-you-batman.jpeg.

To confirm further, I checked stream:http and stream:dns.

![Image 29](images/screenshot-29.png)

Confirmed — this domain is the Command and Control server the attacker contacted after gaining control of the server.

## Phase 5: Post-Incident Threat Intelligence & Attribution

With the C2 domain prankglassinebracket.jumpingcrab.com identified, it could be tied to infrastructure pre-staged against Wayne Enterprise. I used online threat intel sources (Robtex, VirusTotal) to find associated IPs, domains, and email addresses.

First, Robtex on the domain jumpingcrab.com:

![Image 30](images/screenshot-30.png)

This surfaced other subdomains associated with jumpingcrab.com, along with the following DNS trace:

![Image 31](images/screenshot-31.png)

Next, looking up 23.22.63.114 on the same threat lookup site:

![Image 32](images/screenshot-32.png)

Some domains here look similar to the Wayne Enterprise site.

Continuing on VirusTotal:

![Image 33](images/screenshot-33.png)

This surfaced the domain www.po1s0n1vy.com, associated with our attacker, so I searched that next.

![Image 34](images/screenshot-34.png)

Under the Relations tab, a personal domain, lillian.po1s0n1vy.com, appeared — potentially tied to the attacker.

![Image 35](images/screenshot-35.png)

The domain was listed for sale, so I pivoted to historical data instead.

![Image 36](images/screenshot-36.png)

Historical passive DNS and WHOIS records were available under the Details tab on VirusTotal.

![Image 37](images/screenshot-37.png)

The associated IP addresses here confirm the attacker's C2 server IP, 23.22.63.114.

To find out more about the identity behind the personal domain lillian.po1s0n1vy.com:

![Image 38](images/screenshot-38.png)

Historical WHOIS records exposed the registrant email address lillian.rose@po1s0n1vy.com. This confirmed the attack infrastructure and C2 servers were operated by the threat actor handle Lillian (Po1s0n1vy).

## Phase 6: Secondary Payload & Malware Identification

I started by looking up the IP 23.22.63.114 on ThreatMiner.

![Image 39](images/screenshot-39.png)

This revealed an associated sample with MD5 hash c99131e0169171935c5ac32615ed6261. I converted this to its SHA-256 equivalent (9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8) and submitted it to VirusTotal to check vendor detections.

![Image 40](images/screenshot-40.png)

I continued the search on hybrid-analysis.com using the same SHA-256 hash to find more about the malware.

## Indicators of Compromise (IOC) Table

| Indicator Type | Value / Artifact | Description |
|---|---|---|
| Malicious Domain | po1s0n1vy.com | Threat actor primary root domain |
| C2 Host FQDN | prankglassinebracket.jumpingcrab.com | Dynamic DNS Command & Control host (Port 1337) |
| Attacker IP (Scan/Exploit) | 40.80.148.42 | Scanner IP (Acunetix) & manual login source |
| Attacker IP (Brute/C2) | 23.22.63.114 | Automated brute-force source & C2 server |
| Compromised Target IP | 192.168.250.70 | Internal Joomla web server host |
| Uploaded Trojan Binary | 3791.exe | Trojanized ApacheBench binary uploaded to host |
| Defacement Asset URL | /poisonivy-is-coming-for-you-batman.jpeg | Web defacement asset payload |
| Secondary Payload Name | MirandaTateScreensaver.scr.exe | Secondary backdoor executable |
| Primary Malware SHA-256 | ec78c938d8453739ca2a370b9c275971ec46caf6e479de2b2d04e97cc47fa45d | Hash for uploaded 3791.exe payload |
| Secondary Backdoor SHA-256 | 9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8 | Hash for MirandaTateScreensaver.scr.exe |
| Adversary Email / Handle | lillian.rose@po1s0n1vy.com / Lillian | Unmasked threat actor identity |

## Remediation & Security Recommendations

1. Perimeter Isolation & Network Blocking
   * Immediately block all inbound and outbound traffic associated with threat actor IP addresses 23.22.63.114 and 40.80.148.42 at the perimeter firewall (Fortigate UTM).
   * Implement DNS sinkhole rules across internal DNS servers for malicious domains po1s0n1vy.com and dynamic C2 host prankglassinebracket.jumpPhase 7: Remediation & Security Recommendationsingcrab.com.

2. Endpoint Detection & Response (EDR) Hash Blocks
   * Deploy global EDR file execution blocks for primary trojan payload 3791.exe (SHA-256: ec78c938d8453739ca2a370b9c275971ec46caf6e479de2b2d04e97cc47fa45d).
   * Deploy execution blocks for secondary backdoor payload MirandaTateScreensaver.scr.exe (SHA-256: 9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8).

3. Credential Hardening & Identity Management
   * Enforce an enterprise-wide mandatory credential reset for all administrative accounts on the Joomla CMS platform.
   * Terminate all active administrative web sessions and audit user accounts to ensure no persistence or unauthorized backdoors were established.
   * Enforce strong password complexity policies to eliminate vulnerable credentials (such as "batman").

4. Host Containment & Web Application Hardening
   * Isolate target web server 192.168.250.70 from the internal network to perform full forensic disk imaging and eradicate uploaded web shells (agent.php) and malicious binaries.
   * Audit and patch the Joomla web CMS framework to mitigate known vulnerabilities targeted by automated scanning tools like Acunetix.
   * Restrict direct external access to administrative portals (/joomla/administrator/index.php) via IP whitelisting or VPN-only access.
