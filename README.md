Experimental tool made while learning about ntlm relay to/from various protocols and socks proxying. There's nothing novel here, I just wanted to understand ntlmrelayx better by reimplementing some of the core features with the help of ai.

# features
- handles multi relay from smb/http connections to smb/ldap/ldaps/http/https
- user enumeration sent on the first connection (using a fake type 2 ntlm response)
- multi user relay with session tracking
- serves wpad files to compliment mitm6 poisoning tools
- special handler for CONNECT (proxy) requests coming in since they don't respond to redirects and I couldn't find a better way to handle that in an multi relay environment. This allows us to use CONNECT requests when multirelay is enabled
- experimental feature to automatically extract CAs from a tls cert over ldaps during relays. it will also attempt to enumerate the CA via ldap queries. if found, it will check for the CA's web enrollment endpoint and add it to the targets list for esc8. this allows you to take the first successful relay to esc8
- automatically dump the domain via ldap
- makes an effort to print all the relevant info during each step in -verbose mode.
- automatically establishes a socks proxy connection on successful relays and dumps a proxychains config to use with it.

# example
multi relay to smb/http/ldaps with -dump and -find-ca
<img width="936" height="968" alt="image" src="https://github.com/user-attachments/assets/e4633dd2-8821-434f-a2da-1ce3d897da8c" />

also allows for session management (so it doesn't repeat successful relays) and socks proxy tracking
<img width="904" height="472" alt="image" src="https://github.com/user-attachments/assets/5f2b6edf-714b-4e10-b29c-2d397a107796" />



# todo?
- kerberos relaying
- send fake type 2 SMB back to check what user is attempting authentication
- support deny and allow lists for users
  - tweak different actions on a per user basis (if admin, do this)
- socks features
  - max keep alive time on tunnels
  - swap to tcp keep alives instead of ldap
  - kill tunnel
  - add target
  - add up time to socks table
  - add keep alive counter to socks table
- integrate pretender or other dns poisoner somehow?
  - support stop/start of pretender
  - support auto dns poisoning blacklisting for known hosts/users. might allow tool to run for a long time to target specific users without knowing where they might come from?
- starttls for ldap
- relay to mssql
- relay to winrm
- change debug logging to include verbose logging
  - probably remove debugging logging or just send it to a file
- tweak wpad file contents
  - ipv4, ipv6?
- tweak automatic enum
  - fix extra 302 after finding-ca
  - change ca lookup to dns instead of ldap query?
  - add auto sccm finder/realy?
  - convert to bloodhound compatiable json dump
  - move away from obclass=* query
- remove/change error messages being sent to victims over http, change success message from 200
- check ldap message structures mirror windows computers
- chnage server useragent sent with http connections

# credits 
ntlmrelayx - https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py
