Year3: Developing Secure Software module: (group) coursework1: secure webServer

Simple Python/Flask webserver to demonstrate resistance to attacks.

Assignment spec sheet forbid use of any security or security-adjacent library or plug ins. 
reCaptcha and encryption had to be replaced with less secure but "implemented by hand" versions. 
(e.g. the simple caesar cipher encryption was deemed "better" than a working AES as it had been implemented manually). 
The inline API keys (despite only being valid for localhost and expiring after a week) have been redacted (along with the server-secret-key) to prevent any unneeded alerts by gitGuardian.
The SSL '.pem' files have also not been included for the above reason.

Group work. 
Own contributions focussed mainly on:
+ Research and group organisation
+ Code refactoring and merging
+ Cross-site-scripting mitigation
+ SQL-injection mitigation
+ HTML pages
+ Javascript
+ Password authentication
+ reCaptcha (prior to manual reimplementation by another member)
+ SSL certificates (self-signed)
+ Mitigation of session hijacking
+ Database field encryption
