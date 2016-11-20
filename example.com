; example.com
$TTL 3600
example.com. IN     SOA    a.root-servers.net. dnsmaster@trashmail.com. (
				2016112001  ; Serial
				3H          ; refresh after 3 hours
				1H          ; retry after 1 hour
				1W          ; expire after 1 week
				1D)         ; minimum TTL of 1 day

	; Name Server
	IN	NS	a.root-servers.net.	; VeriSign verteilt (anycast)
	IN	NS	e.root-servers.net.	; ns.nasa.gov, Mountain View, Kalifornien, USA
	IN	NS	l.root-servers.net.	; ICANN verteilt (anycast)

	; Mail Exchanger
	IN	MX	50 mx1.mail.com.	; Your Mail Server

example.com.			IN A		85.214.123.64
