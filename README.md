Incident Case: BOTSv1 Web Compromise & C2 Infrastructure Analysis
Target Organization: Wayne Enterprises (imreallynotbatman.com)
Analyst: Prince Bhattarai
Date: July 2026
Framework: Lockheed Martin Cyber Kill Chain / NIST SP 800-61

Executive Summary

On August 10, 2016, internal monitoring systems detected a successful web defacement attack targeting Wayne Enterprises' public web application (www.imreallynotbatman.com)

Subsequent forensic investigation into enterprise SIEM (Splunk) logs revealed a multi-stage intrusion executed by an external adversary. The threat actor initially conducted automated web vulnerability scans against the Joomla CMS architecture, followed by a brute-force credential stuffing attack against the administrative portal (/joomla/administrator/index.php).

Upon gaining unauthorized administrative access, the adversary uploaded a trojanized binary (3791.exe) disguised as an ApacheBench utility and established outbound Command & Control (C2) communication to download defacement assets (/poisonivy-is-coming-for-you-batman.jpeg). Threat intelligence pivoting across OSINT platforms (VirusTotal, ThreatMiner, Hybrid Analysis) linked the infrastructure to adversary handle Lillian (po1s0n1vy.com), C2 IP 23.22.63.114, and secondary backdoor payloads (MirandaTateScreensaver.scr.exe). Immediate containment actions included IP/domain perimeter blocks, credential resets, and endpoint signature deployments.

To systematically track the adversary’s footprint across our enterprise environment, this investigation maps log evidence against the Lockheed Martin Cyber Kill Chain framework. Logs were analyzed using Splunk Enterprise across web stream, intrusion detection (Suricata), firewall (Fortigate UTM), host system (Windows Event Logs), and endpoint threat detection (Sysmon) sources.

File name: botsv1public data set by splunk
https://github.com/splunk/botsv1is the source.

Phase 1: Reconnaissance & Vulnerability Scanning

To begin the investigation, I queried Splunk for all event logs related to our web domain (imreallynotbatman.com) to identify any initial scanning or suspicious activity. S

Search Query: index=botsv1 imreallynotbatman.com

![Image 1](images/screenshot-01.png)

Next, I filtered by the stream:http sourcetype to inspect web traffic and examined the src_ip field.

Search Query:index=botsv1 imreallynotbatman.com sourcetype=stream:http

![Image 2](images/screenshot-02.png)

Looking at the src_ip distribution in the HTTP stream logs, two external IP addresses stood out: 40.80.148.42 (Accounting for 93.4% of total requests) 23.22.63.114 (Accounting for 6.6% of total requests) Since IP 40.80.148.42 generated the vast majority of inbound traffic, I am going to check our Suricata Intrusion Detection System (IDS) logs to see if any security alerts were triggered by this IP address.

So now we will run the suricata query

Search Query: index="botsv1" imreallynotbatman.com sourcetype="suricata"src_ip="40.80.148.42"

![Image 3](images/screenshot-03.png)

So this query is showing the logs from suricata source that is from the ip address we are investigating. So now we will go to the alerts section of suricata to see what’s up.

![Image 4](images/screenshot-04.png)

As shown in the picture above, the Suricata alert.signature field revealed high-volume alerts for Cross-Site Scripting (XSS), SQL Injection (SQLi), and XML External Entity (XXE) attempts. To confirm what tool generated these alerts, I navigated back to the HTTP stream logs to inspect the User-Agent strings.

Search Query:: index=botsv1 imreallynotbatman.com sourcetype="stream:http"

![Image 5](images/screenshot-05.png)

So here we can see strings of useragent and very easily we can spot that there are two red flags, the “Python-urllib/2.7” and ";print(md5(acunetix_wvs_security_test));$a="which has the name of acunetix which is a Web Vulnerability scanner so since, this confirmed that the attacker at IP 40.80.148.42 utilized the Acunetix Web Vulnerability Scanner to automatically probe and map our web application for security flaws prior to launching exploitation attempts.

So this sums up Phase 1, Reconnaissance & Vulnerability Scanning

Phase 2: Exploitation & Brute-Force Attack

Now we move towards the exploitation phase to look at the potential exploitation attempt from the attacker against our web server and see if the attacker got successful in exploiting or not.

Now we want to count the number of counts by each source IP against the webserver.

So we run this query Search Query:index=botsv1 imreallynotbatman.com sourcetype=stream* | stats count(src_ip) as Requests by src_ip | sort – Requests

![Image 6](images/screenshot-06.png)

Now we will narrow down the result to show requests sent to our web server, whichhas the IP 192.168.250.70

Search Query: index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70"

![Image 7](images/screenshot-07.png)

Here we can see on the src_ip interesting field that there are three ips, one is our local ip and the other two are remote ips that originated the HTTP traffic towards our webserver.

Now we can also look at the http_method to see what kind of activity the attacker is doing so to do so I can navigate to the http_method interesting field and look at what the attacker is attempting to do.

![Image 8](images/screenshot-08.png)

We can see that most of the requests coming to our server through the POST request so now I will run the query :

Search Query:index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST

To see what kind of traffic is coming through POST and navigate to its src_ip interesting field.

![Image 9](images/screenshot-09.png)

The result in the src_ip field shows two IP addresses sending all the POST requests to our server.

So then when I navigated to the URI interesting tab

![Image 10](images/screenshot-10.png)

We can see that our webserver runs on Joomla CMS in the backend.

So since the uri contains the login page to access the web portal, I should examine the incoming traffic into this admin panel next to check for a potential brute force attack on it.

So after I did a little internet digging and looking at the URI field I found out that the url for the Jomma’s login portal url is

https://www.joomla.org/administrator/index.php

![Image 11](images/screenshot-11.png)

So using this information I can use the search query

Search Query: index=botsv1 imreallynotbatman.com sourcetype=stream:http dest_ip="192.168.250.70"  uri="/joomla/administrator/index.php"

So now we will look at the form_data field from the intresting fields because it shows all the request that has been sent from the admin login page to the server

![Image 12](images/screenshot-12.png)

Since we can assume that the attacker might have tried multiple credentials to gain access, we need to dig deeper for the clear picture so I am gonna use the following query to do so.

Search Query: index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST uri="/joomla/administrator/index.php" | table _time uri src_ip dest_ip form_data

I am making this query for a cleaner view of the events that has taken place so it would be easy to spot differences.

![Image 13](images/screenshot-13.png)

Here we can see a IP 23.22.63.114was attempting brute forcing andthe time elapsed between the event was short so the attacker is probably using an automated tool.

Now to make it easier to track I am going to use regex. To extract all the password values found against the passwd in the logs.

So using the following query:

Search Query: index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST form_data=*username*passwd* | rex field=form_data "passwd=(?<creds>\w+)"  | table src_ip creds

![Image 14](images/screenshot-14.png)

We have extracted the passwords being used against the username admin on the admin panel of the webserver. If we examine the fields in the logs, we will find two values against the field http_user_agent as shown below:

![Image 15](images/screenshot-15.png)

We can see here through the user agent that the attacker used python scripting to automate the brute force attack.

![Image 16](images/screenshot-16.png)

Finally, we can add the time field for a clear picture of the events and This result clearly shows a continuous brute-force attack attempt from an IP 23.22.63.114 as well as 1 password attempt batman from IP 40.80.148.42 using the Mozilla browser.

Phase 3: Installation Phase

So since we know that the website imreallynotbatman.com has been compromised we can assume that the attacker using python script to automate getting the correct password is already setting up backdoors in the system,

To begin an investigation, we first would narrow down any http traffic coming into our server 192.168.250.70 containing any sort of executables or .exe files..

We can do this by using the splunk query

Search Query:index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" *.exe

![Image 17](images/screenshot-17.png)

Here I have found two files an executable file 3791.exe and a PHP file agent.php, so I am gonna look for any hints of the IP address we found out earlier attack to see if its the same adversary. I will be using the following query:

Search Query:index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70""part_filename{}"="3791.exe"

![Image 18](images/screenshot-18.png)

My suspicions were true, this ip was what we found earlier so its clear that the hacker who got unauthorized access to our website uploaded the 3791.exe file. We need to escalate this and need to find out if this file executed onto our system so we need to narrow down our search.

![Image 19](images/screenshot-19.png)

Looking at the source file from the above picture we can see that 3791.exe was executed on
1. xmlwineventlog
2. wineventlog
3. fortigate_utm

To further confirm this I will be looking at the event logs of xmlwineventlog.

![Image 20](images/screenshot-20.png)

This shows that 3791.exe was in fact executed which means our system is compromised.

So now I am going to do a bit of research on the malware, I can use the logs and review them for hashes and search the internet for matches against it to get an insight to what kind of malware we are dealing with.

![Image 21](images/screenshot-21.png)

Here, we can see where 3791.exe was first executed, I am going to use the hashec78c938d8453739ca2a370b9c275971ec46caf6e479de2b2d04e97cc47fa45dto find any information available of it on virus total.

![Image 22](images/screenshot-22.png)

And here we go, we have found information about the trojan, that this binary is a trojanized version of the ApacheBench (ab.exe) utility used for backdoors and to hide malicious behavior.

Phase 4: Actions on Objectives & Web Defacement

So now that we have figured out that someone has broke into our system and defaced our website, its pretty helpful to find out what exactly caused the defacement.

So i will be investigating the SURICATA logs to find out what security rules were triggered. So to do this I will run the following query into splunk.

Search Query:index=botsv1 dest=192.168.250.70 sourcetype=suricata

![Image 23](images/screenshot-23.png)

Since the IP communicating with the server are not external IP we should see if any iP from our server is communicating outside our server and to do this we can use the query below.

Search Query: index=botsv1 src=192.168.250.70 sourcetype=suricata

![Image 24](images/screenshot-24.png)

Here we see three external IPs towards which our web server initiates the outbound traffic. There is a large chunk of traffic going to these external IP addresses, which could be worth checking.

So we will be pivoting each of these ip addresses to see and find out what kind of communication and traffic is being carried out.

So, for the first IP search we can use the query

Search Query: index=botsv1 src=192.168.250.70 sourcetype=suricata dest_ip=23.22.63.114

![Image 25](images/screenshot-25.png)

We can see that there are 2 PHP files and one jpeg file, The jepg file looks relevant so I will check on this further to see where it came from.

So I will now use the following query to do so and format the output in a clear way.

Search Query: index=botsv1 url="/poisonivy-is-coming-for-you-batman.jpeg" dest_ip="192.168.250.70" | table _time src dest_ip http.hostname url

![Image 26](images/screenshot-26.png)

The end result clearly shows a suspicious jpeg poisonivy-is-coming-for-you-batman.jpeg was downloaded from the attacker's host prankglassinebracket.jumpingcrab.com that defaced the site.

Similarly we can also check out the fortigate firewall to see if it has any SQL attempt from the attacker's IP 40.80.148.42, so to do this I will search for the following query. index=botsv1 src_ip="40.80.148.42" sourcetype="fortigate_utm"

![Image 27](images/screenshot-27.png)

Here we can see that HTTP.URI.SQL.Injection was the rule triggered during the SQL injection attempt.

So now that we have found out what caused the defacement , we also know that the attacker was using a DynamicDNS cause we saw a domain name in the logs earlier and not a static ip address.

So we will further our search using fortigate_utm, using the following query

Search Query: index=botsv1 sourcetype=fortigate_utm"poisonivy-is-coming-for-you-batman.jpeg"

![Image 28](images/screenshot-28.png)

So after running the query, the fields on the left panel and the field url contains the FQDN prankglassinebracket.jumpingcrab.com:1337/poisonivy-is-coming-for-you-batman.jpeg so we have our answer.

But to further confirm this I will search for it on another log source stream:http or I can also use stream:dns. I will check them.

![Image 29](images/screenshot-29.png)

Here we can confirm it so we have identified the suspicious domain as a Command and Control Server, which the attacker contacted after gaining control of the server.

Phase 5: Post-Incident Threat Intelligence & Attribution

Since we have found out the domain name prankglassinebracket.jumpingcrab.com which is associated with the attack we are facing, it could be tied to the domains that may potentially be pre-staged to attack Wayne Enterprise.

So, now I will use some online threat sites like robtex and virus total to find any information like IP addresses/domains / Email addresses associated with this domain which could help us know more about this adversary.

First we will use robtex to search the domain jumpingcrab.com

![Image 30](images/screenshot-30.png)

So,i looked it up found out these other subdomains associated with jumpingcrab.com as well as the following DNS Trace,

![Image 31](images/screenshot-31.png)

Now I will look up the ip we found earlier 23.22.63.114 on this threat lookup site to see what results it gives us.

![Image 32](images/screenshot-32.png)

In this serarch results we can see that some domains that look pretty similar to the WAYNE Enterprise site.

Now to further our search, I will use virus total to continue my investigation.

![Image 33](images/screenshot-33.png)

Here in the list we can see domain.www.po1s0n1vy.comwhich is associated with our attacker so I will use this url to search again.

![Image 34](images/screenshot-34.png)

So here we can look at the relations tab and see a personal domain lillian.po1s0n1vy.comwhich could be tied to the attacker so I will now find more about this person’s registered domain.

![Image 35](images/screenshot-35.png)

But unfortunately the domain is on sale so we need to change our approach and look for its historical data.

![Image 36](images/screenshot-36.png)

So I pivoted to historical passive DNS and WHOIS records archived in VirusTotal under the Details tab.

![Image 37](images/screenshot-37.png)

Here looking at the associated IP addresses I found out the external ip address 23.22.63.114 of the attacker's C2 server. So this confirms that this was the attacker.

So to find out more about her I will use another source to find out who this person is as shown below using the personal domain, lillian.po1s0n1vy.com we found out on virus total.

![Image 38](images/screenshot-38.png)

Historical WHOIS records exposed the registrant email address lillian.rose@po1s0n1vy.com. This confirmed that the attack infrastructure and C2 servers were operated by the threat actor handle Lillian (Po1s0n1vy). 

Phase 6: Secondary Payload & Malware Identification

I will start our investigation by looking for the IP 23.22.63.114 on the Threat Intel site ThreatMiner.

![Image 39](images/screenshot-39.png)

To hunt for secondary backdoors, I queried the C2 IP (23.22.63.114) on ThreatMiner, revealing an associated sample with the MD5 hash c99131e0169171935c5ac32615ed6261.I converted this to its SHA-256 equivalent (9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8) and submitted it to VirusTotal to inspect vendor detections.

![Image 40](images/screenshot-40.png)

Now I have continued my search to hybrid-analysis.comto find more about the malware using the SHA256 hash we uncovered as shown above.

Indicators of Compromise (IOC) Table

Indicator Type | Value / Artifact | Description
Malicious Domain | po1s0n1vy.com | Threat actor primary root domain 
C2 Host FQDN | prankglassinebracket.jumpingcrab.com | Dynamic DNS Command & Control host (Port 1337) 
Attacker IP (Scan/Exploit) | 40.80.148.42 | Scanner IP (Acunetix) & manual login source 
Attacker IP (Brute/C2) | 23.22.63.114 | Automated brute-force source & C2 server 
Compromised Target IP | 192.168.250.70 | Internal Joomla web server host 
Uploaded Trojan Binary | 3791.exe | Trojanized ApacheBench binary uploaded to host 
Defacement Asset URL | /poisonivy-is-coming-for-you-batman.jpeg | Web defacement asset payload 
Secondary Payload Name | MirandaTateScreensaver.scr.exe | Secondary backdoor executable 
Primary Malware SHA-256 | ec78c938d8453739ca2a370b9c275971ec46caf6e479de2b2d04e97cc47fa45d | Hash for uploaded 3791.exe payload 
Secondary Backdoor SHA-256 | 9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8 | Hash for MirandaTateScreensaver.scr.exe
Adversary Email / Handle | lillian.rose@po1s0n1vy.com / Lillian | Unmasked threat actor identity