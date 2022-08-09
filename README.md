Secure Programming in Go

#### Background

"First rule of computer security: don't buy a computer. Second rule: if you buy one, don't turn it
on. [Third rule: if you turn it on, don't connect it to a network]" ~ The Dark Avenger

As a developer, there are a lot of bad actors out there who would like to gain access to your code.

The idea of understanding security as a developer is not to defend yourself against everything but to guard yourself
against the common cases. The idea is to secure yourself so that hackers and other bad actors move to the easier
targets.

#### CVEs (Common Vulnerabilities and Exposures)

This is a database of common security issues.

1. https://www.cvedetails.com/
2. Synk [website](https://snyk.io/blog/go-security-cheatsheet-for-go-developers/)
3. Golang Announce Google [Group](https://groups.google.com/g/golang-announce)

#### OWASP Top Ten

This list contains the top ten most critical security vulnerabilities for web applications. Below is the list as of
2021:

1. [Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
2. [Cryptographic failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
3. [Injection](https://owasp.org/Top10/A03_2021-Injection/)
4. [Insecure design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
5. [Security misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
6. [Vulnerable and outdated components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)
7. [Identification and authentication failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
8. [Software and data integrity failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
9. [Security logging and monitoring failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)
10. [Server-Side Request Forgery](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)

##### 1. Broken Access Control

Access control enforces policy such that **_users cannot act outside their intended permissions_**. Failures typically
lead to unauthorised information disclosure, modification, or destruction of all data performing a business function
outside the user's limits. Common access control vulnerabilities include:

* Violation of the principle of **least privilege** or **deny by default**, where access should only be granted for
  particular capabilities, roles, or users, but is available to everyone. Elevation of privilege. Acting as a user
  without logging in or acting as an admin when logged in as a user.
* Metadata manipulation, such as replaying or tampering with a JWT access control token, or a cookie or hidden field
  manipulated to elevate privileges or abusing JWT invalidation.
* Accessing API with missing access controls for POST, PUT and DELETE. Permitting viewing or editing someone else's
  account, by providing its unique identifier (insecure direct object references).
* Bypassing access control checks by modifying the URL, internal application state, or the HTML page, or by using an
  attack tool modifying API requests.

##### 2. Cryptographic Failures (Sensitive Data Exposure)

These result from failures related to cryptography (or lack thereof) which often lead to exposure of sensitive data. The
first thing is to determine the protection needs of data in transit and at rest. For example, passwords, credit card
numbers, health records, personal information, and business secrets require extra protection, mainly if that data falls
under privacy laws, e.g. EU's General Data Protection Regulation (GDPR), or regulations, e.g. financial data protection
such as Payment Card Industry Data Security Standard (PCI DSS). For all such data, the following questions should be
considered:

* Is any data transmitted in clear text?
* Are any old or weak cryptographic algorithms or protocols used either by default or in older code?
* Are default crypto keys is use, weak crypto keys generated or re-used, or is proper key management or rotation
  missing?
* Is encryption not enforced, e.g., are any HTTP headers security directives or headers missing?
* Is the received server certificate and the trust chain properly validated?
* Are passwords being used as cryptographic keys in absence of a password base key derivation key?
* Are deprecated hash functions such as MD5 or SHA1 in use, or are non-cryptographic hash functions used when
  cryptographic hash functions are needed?
* Are deprecated cryptographic padding methods such as PKCS number 1 v1.5 in use?
* Are cryptographic error messages or side channel information exploitable, for example in the form of padding oracle
  attacks?

##### 3. Injection

An application is vulnerable to injection attack when:

* User-supplied data is not validated, filtered, or sanitized by the application.
* Dynamic queries or non-parameterized calls without context-aware escaping are used directly in the interpreter.
* Hostile data is used within object-relational mapping (ORM) search parameters to extract additional, sensitive
  records.
* Hostile data is directly used or concatenated. The SQL or command contains the structure and malicious data in dynamic
  queries, commands, or stored procedures.

##### 4. Insecure Design

This category focuses on risks related to design and architectural flaws, with a call for more use of threat modeling,
secure design patterns, and reference architectures. Notable Common Weakness Enumerations (CWEs)
include [Trust Boundary Violation](https://cwe.mitre.org/data/definitions/501.html)
, [Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)

##### 5. Vulnerable and Outdated Components

One is most likely vulnerable to this vulnerability if:

* They do not know the versions of all components they use (both client-side and server-side). This includes components
  directly used as well as nested dependencies.
* If the software is vulnerable, unsupported, or out of date.
* If they do not scan for vulnerabilities regularly and subscribe to security bulletins related to the components in
  use.
* If they do not fix or upgrade the underlying platform, frameworks, and dependencies in a risk-based, timely fashion.
  This commonly happens in environments when patching is a monthly or quarterly task under change control, leaving
  organizations open to days or months of unnecessary exposure to fixed vulnerabilities.
* If software developers do not test the compatibility og updated, upgraded, or patched libraries.

##### 6. Identification and Authentication Failures

Confirmation of the user's identity, authentication, and session management is critical to protect against
authentication-related attacks. There may be authentication weaknesses if the application:

* Permits automated attacks such as credential stuffing, where the attacker has a list of valid usernames and passwords.
* Permits brute force or other automated attacks.
* Permits default, weak, or well known passwords, such as "Password1" or "admin/admin".
* Uses weak or ineffective credential recovery and forgot-password processes, such as knowledge-based answers, which
  cannot be made safe.
* Uses plain text, encrypted, or weakly hashed passwords data stores.
* Has missing or ineffective multi-factor authentication.
* Reuse session identifier after successful login.
* Does not correctly invalidate Session IDs. User sessions or authentication tokens aren't properly invalidated during
  logout or a period of inactivity.

##### 7. Software and Data Integrity Failures

This category focuses on making assumptions related to software updates, critical data, and CI/CD pipelines without
verifying integrity. Notable Common Weaknesses Enumerations (CWEs) include Inclusion of Functionality from Untrusted
Control Sphere, Download of COde Without Integrity Check and Deserialization of Untrusted Data

Prevention include:

* Using digital signatures or similar mechanisms to verify the software or data is from the expected source and has not
  been altered.
* Ensure libraries and dependencies, such as npm or Maven, are consuming trusted repositories.
* Ensure that a software supply chain security tool, such as OWASP Dependency Check or OWASP CycloneDX, is used to
  verify that components do not contain known vulnerabilities.
* Ensure that there is a review process for code and configuration changes to minimize the chance that malicious code or
  configuration could be introduced into your software pipeline.
* Ensure that your CI/CD pipeline has proper segregation, configuration, and access control to ensure the integrity of
  the code

##### 8. Security Logging and Monitoring Failures

This category is to help detect, escalate and respond to active breaches. Without logging and monitoring, breaches can
go undetected. Insufficient logging, detection, monitoring, and active response occurs any time:

* Auditable events, such as logins, failed logins, and high-value transactions, are not logged.
* Warning and errors generate no, inadequate, or unclear log messages.
* Logs of applications and APIs are not monitored for suspicious activity.
* Logs are only stored locally.
* Appropriate alerting thresholds and response escalation processes are not in place or effective.
* Penetration testing and scans by dynamic application security testing (DAST) tools do not trigger alerts.
* The application cannot detect, escalate, or alert for active attacks in real-time or near real-time.

##### 9. Server-Side Request Forgery (SSRF)

SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. This
allows an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected
by a firewall, VPN, or another type of network access control list (ACL)

Prevention can be done in the various network layers as follows:

###### Network layer

* Segment remote resource access functionality in separate networks to reduce the impact of SSRF
* Enforce "deny by default" firewall policies or network access control rules to block all but essential intranet
  traffic

###### Application layer

* Sanitize and validate all client-supplied input data
* Enforce teh URL schema, port, and destination with a positive allow list
* Do not send raw responses to clients
* Disable HTTP redirections
* Be aware of the URL consistency to avoid attacks such as DNS rebinding and "time of check, time of use" race
  conditions.










