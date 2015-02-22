viewssld — SSL decryption daemon for Snort
--------------------
viewssld is a free, open source, non-terminating SSLv2/SSLv3/TLS traffic decryption daemon for Snort, and other Network Intrusion Detection Systems (IDS).

### Disclaimer
Before carrying on working on getting it compiled, it’s worth thinking about this:
The issue that viewssld faces in today’s world is that more and more SSL/TLS servers are using some form of perfect forward secrecy (“PFS”, usually a flavour of Diffie-Hellman) for key agreement, rather than using the server’s private key to encrypt the pre-master secret. There’s lots of maths ‘n’ stuff here: http://vincent.bernat.im/en/blog/2011-ssl-perfect-forward-secrecy.html


The bottom line is that viewssld’s days are numbered unless you cripple your server’s SSL/TLS configuration to not use PFS (thereby scoring poorly on the SSL Labs test <https://www.ssllabs.com/ssltest/> !), so it (viewssld) doesn’t have much of a future outside of some very specific cases. I guess that in a PFS world the best way to do this would be to terminate SSL/TLS on a box in front of your servers and have your NSM tap on the unencrypted link between the two?

by @alecrwaters

### Requirements
* libpcap
* libssl (openssl)
* libdssl, you can download it from here: https://github.com/downloads/plashchynski/viewssld/libdssl-2.1.1.tar.gz

### Installation and Usage
See http://resources.infosecinstitute.com/ssl-decryption/ for more details. Please note that libdssl is no longer available at the atomiclabs svn archive so the libdssl download link in the article doesn't work. You can download libdssl here: https://github.com/downloads/plashchynski/viewssld/libdssl-2.1.1.tar.gz

### Support
Need some help? Feel free to create an issue https://github.com/plashchynski/viewssld/issues
