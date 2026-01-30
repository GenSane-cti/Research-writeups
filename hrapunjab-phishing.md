# Hranpunjab Phishing

## Executive Summary
This write-up analyzes a targeted phishing campaign observed on 26 January 2026, aimed at customers of the Belgian bank **Argenta** and users of the French government traffic fine service (**amendes.gouv.fr**). The phishing email used Dutch and French language content and impersonated official communications to increase credibility among its intended audience.

The campaign leveraged legitimate services such as **SurveyMonkey** and **DigitalOcean Spaces** to create a multi-stage redirection chain, ultimately leading victims to attacker-controlled domains designed to mimic legitimate authentication portals (e.g., “Argenta Digipass”). This approach helps obscure the final destination and evade basic email and URL filtering controls.

Infrastructure analysis identified a shared IP address (**162.214.80[.]31**), recently issued **Let’s Encrypt certificates**, and multiple lookalike domains used to impersonate banking and government services. Passive DNS and certificate data indicate the campaign is recent and coordinated, with infrastructure reused across multiple brands and services.

Although the final phishing pages were no longer accessible at the time of analysis, the targeting, branding, and infrastructure strongly indicate a **credential-harvesting operation**, likely intended to enable financial fraud. The campaign demonstrates moderate operational maturity through rapid domain rotation, abuse of trusted cloud platforms, and precise regional targeting.

## Email Analysis
Below is a phishing email received on January 26th, 2026, at 00:33.
<img width="1426" height="1075" alt="Argenta" src="https://github.com/user-attachments/assets/0b596f1d-a9f6-424d-945d-ece56c434b49" />

When looking at the email, we can see that it is targeted towards users of the Belgian bank Argenta. The email is written in Dutch and French, which is typical for Belgian users. The email text contains one peculiarity (apart from being very plain): In the Dutch text the attacker writes "Argenta Ban k". This is an obvious mistake. It should be written as "Bank". 

The email contains two links and one reply-to email, and uses surveymonkeyuser.com as the initial domain to send the email from. The two included links are the same.
- https://fr.surveymonkey.com/tr/v1/te/QgNoOCWzi_2FRmUMiiRwV2yRB_2B2qCgEVdLq3zR55lyMywArM6bcn9N66eHzpmFRy80NSWQY_2BZPhulza_2FUyD8EminTN1oT5Puh3qlziccU6wK_2FevoiazbVK4MrDzeOsCWlv777kfkCy5FnMODfzgzks5L9_2F2RzTw0xP_2FwGo5ie6rThpLdmUEdo_2FCzVSYY0sxXEt0fMSUEjdyfQDfg8pL0YExgO97EJYq8VNGog1rQlaEyOsuaFKrf93GhaPgzu9fXEB
- https://fr.surveymonkey.com/tr/v1/te/QgNoOCWzi_2FRmUMiiRwV2yRB_2B2qCgEVdLq3zR55lyMywArM6bcn9N66eHzpmFRy80NSWQY_2BZPhulza_2FUyD8EminTN1oT5Puh3qlziccU6wK_2FevoiazbVK4MrDzeOsCWlv777kfkCy5FnMODfzgzks5L9_2F2RzTw0xP_2FwGo5ie6rThpLdmUEdo_2FCzVSYY0sxXEt0fMSUEjdyfQDfg8pL0YExgO97EJYq8VNGog1rQlaEyOsuaFKrf93GhaPgzu9fXEB
- webapp@argentaglobal-service.webapp.hrapunjab.com
- member@surveymonkeyuser.com

## Link Analysis
We can use the tool https://urlscan.io to analyze the URL. Before discussing the results, something to notice in the phishing link is the use of a legitimate domain (fr.surveymokey.com) followed by the pattern "/tr/v1/te/". This pattern is often used in phishing to redirect users to the attacker's page.

Below, we can see the results of the urlscan.io analysis.
<img width="1397" height="874" alt="Pasted image 20260126073717" src="https://github.com/user-attachments/assets/fd26e3b1-83a5-46f7-b91e-3b9d08af32c7" />

<img width="1410" height="1206" alt="Pasted image 20260126073815" src="https://github.com/user-attachments/assets/fb3aa0d3-9c64-432e-8721-55e765b77bd4" />

The output shows that there are two successful requests and one failed request:

The original URL from the mail redirects to https://ofcompound[.]fra1.digitaloceanspaces[.]com/quality?https://hotmail.fr via https://healthyminerals[.]tor1[.]digitaloceanspaces[.]com/small?https://name.com/ . Note that these two URLs don't point to a website, but rather to a bucket on digitaloceanspaces.com. This redirect chain reveals the use of DigitalOcean Spaces buckets configured as open redirectors.

In the snippet below, we can see the output from both redirects
``` json
# The original URL leads to the healthyminerals bucket, which includes a redirect to the ofcompound bucket
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="2;url=https://ofcompound.fra1.digitaloceanspaces.com/quality?https://hotmail.fr">
    <title>Redirection...</title>
</head>
</html>

# The ofcompound bucket then redirects to the final destination url https[:]//argenta-digipass.celebstitch[.]com/ARGTE9293?https://hotmail.fr

<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="2;url=https://argenta-digipass.celebstitch.com/ARGTE9293?https://hotmail.fr">
    <title>Redirection...</title>
</head>
</html>
```

The final destination in the redirection chain should have been https://argenta-digipass[.]celebstitch[.]com/ARGTE9293?https://hotmail.fr, but the resource was not available. Note that the URL contains the bank's name (Argenta) and a reference to the authentication mechanism (Digipass). Note that the Digipass service is actually used for Argenta users. With this information, it is likely a targeted phishing campaign.

## Domain Analysis with VirusTotal
We will focus on analyzing the last URL of the redirection chain "https://argenta-digipass%5B.%5Dcelebstitch%5B.%5Dcom/ARGTE9293?https://hotmail.fr"

### HTTPS Certificate

First, look at the last https certificate tied to the argenta-digipass.celebstich[.]com domain shows that it is a Let's Encrypt certificate with a 3-month validity date. The certificate is valid from 2026-01-24 17:26:53 to 2026-04-24 17:26:52, indicating that Argenta is the most recent target in this phishing campaign.

<img width="620" height="321" alt="Pasted image 20260126105858" src="https://github.com/user-attachments/assets/5c80cf17-ad62-48a9-80b0-b6b54f953e63" />

### JARM fingerprint
The JARM fingerprint for the domain is 29d29d15d29d29d00042d42d000000cd600c085f371f8533aaf66051f8e5b1. Using partially free tools like Shodan.io and Censys.io, no additional information was found to pivot on.

### DNS records
The domain resolves to the IP address 162.214.80[.]31, which is also included in the TXT record. The TXT record has the value "v=spf1 +a +mx +ip4:162.214.80.31 ~all", which indicates that this domain is configured to explicitly authorize mail delivery from the IP address 162.214.80[.]31, which is linked to the hosting provider "Bluehost". This is consistent with typical phishing infrastructure.

## Pivot on 162.214.80[.]31

Looking at the passive DNS results in VirusTotal, multiple domains have been registered for this phishing campaign. If we use the date that was in the certificate of the argenta-digipass.celebstich[.]com domain as a filter, the following domains are highly likely to be linked to the same campaign:

<img width="1080" height="932" alt="Pasted image 20260126113450" src="https://github.com/user-attachments/assets/642fed81-9013-414d-bf80-68a6759e4154" />

From these results, it seems that not only Argenta is being targeted, but also the French service for traffic fines with its official website at www.amendes.gouv.fr. Looking at the domain names from the results, it seems not only the celebstich[.]com domain, but also the "hrapunjab[.]com", "kalakaar.co[.]in", and "beginningstep[.]com" domains are used in this campaign.

Further pivoting on the discovered domains, we can deduce that it is highly likely that these are legitimate domains that have been compromised by the attacker. A quick look at the websites hosted at these domains shows the use of the WordPress CMS. A minor observation is that at least two of the domains are Indian.

### WHOIS
Looking at the WHOIS information for each of the malicious domains, they have a few things in common: the administrative/registrant email is set as "e673f847fbe67b8bs@GMAIL.COM," and the Administrative city is set as "Jalandhar". A pivot on this email did not yield any results.
### Files communicating
Looking at which files have been communicating with this IP, not much can be deduced. There are various malicious binaries listed, including the FormBook info stealer malware. The last listed communication was on March 16th, 2025. A common theme amongst these binaries is that a large part of them are info stealers. Since the IP is from a hosting provider, it is hard to directly correlate it with this phishing campaign.

## Conclusion
The discovered phishing campaign is targeting users of the Belgian bank Argenta and the French government service for fines. Looking at the dates of the registered certificates for the various domains, it looks like this is a recent campaign that started over the weekend. The analyzed email is dated January 26th, 2026. 

## Indicators of Compromise
### Infrastructure
```text
162[.]214[.]80[.]31
www[.]argentadigipass-be[.]hrapunjab[.]com
argentadigipass-be[.]hrapunjab[.]com
www[.]argentaglobal-service[.]webapp[.]hrapunjab[.]com
argentaglobal-service[.]webapp[.]hrapunjab[.]com
www[.]amendes-gouv-info[.]hrapunjab[.]com
amendes-gouv-info[.]hrapunjab[.]com
www[.]amendes-gouv-fr[.]kalakaar[.]co[.]in
amendes-gouv-fr[.]kalakaar[.]co[.]in
argenta-digipass[.]celebstitch[.]com
www[.]argenta-digipass[.]celebstitch[.]com
gouv-amendes-fr[.]thebeginningstep[.]com
www[.]gouv-amendes-fr[.]thebeginningstep[.]com
www[.]amendes-gouv[.]thebeginningstep[.]com
hxxps[:]//ofcompound[.]fra1[.]digitaloceanspaces[.]com/quality?
hxxps[:]//healthyminerals[.]tor1[.]digitaloceanspaces[.]com/small?
```
### Certificate thumbprints
```text
89a80629088292db88b60e232c58386cc13684eb
f68099d95bed44a4564c2bf30a49c0082e3fb117
eee696eded1c07fda3fbdfe48753255c3dd25f67
cc3456ebe39db2789194db81bd7be3181fde1ce0
d9a9a3d974eda7479a15f3a4857f5b2664a87d42
3383433e8a513d9e1c29035884a0c698e37d26d4
377436437bb00a37890c52923c496e71d7f85063
```
## Mitre ATT&CK Techniques
``` text
T1566.002 Spearphishing
T1036 Masquerading
T1071.001 Application Layer Protocol: Web Protocols
T1583.003 Acquire Infrastructure: Virtual Private Server
T1583.006 Acquire Infrastructure: Web Services
T1588.005 # Obtain Capabilities: Exploits (Assuming that the attacker compromised the different domains where Wordpress sites were hosted)
```
