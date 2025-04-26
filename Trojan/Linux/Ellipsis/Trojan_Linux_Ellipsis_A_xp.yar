
rule Trojan_Linux_Ellipsis_A_xp{
	meta:
		description = "Trojan:Linux/Ellipsis.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 76 61 72 2f 6c 6f 67 2f 65 76 65 72 79 74 68 69 6e 67 2e 6c 6f 67 } //1 /var/log/everything.log
		$a_01_1 = {6b 69 6c 6c 61 6c 6c 20 73 79 73 6c 6f 67 64 20 72 73 79 73 6c 6f 67 64 } //1 killall syslogd rsyslogd
		$a_01_2 = {2f 62 69 6e 2f 72 6d 20 2d 72 66 20 2f 74 6d 70 2f 2e 2e 2e } //1 /bin/rm -rf /tmp/...
		$a_01_3 = {64 6e 73 6d 61 73 71 20 74 63 70 64 75 6d 70 } //1 dnsmasq tcpdump
		$a_01_4 = {6d 61 78 66 6c 6f 6f 64 } //1 maxflood
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}