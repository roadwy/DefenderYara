
rule DDoS_Win32_UDPFlood{
	meta:
		description = "DDoS:Win32/UDPFlood,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {25 64 2e 25 64 2e 25 64 2e 25 64 2e 69 6e 2d 61 64 64 72 2e 61 72 70 61 2e } //1 %d.%d.%d.%d.in-addr.arpa.
		$a_00_1 = {44 68 63 70 4e 61 6d 65 53 65 72 76 65 72 } //1 DhcpNameServer
		$a_00_2 = {49 63 6d 70 53 65 6e 64 45 63 68 6f } //1 IcmpSendEcho
		$a_02_3 = {bb 00 7d 00 00 8d ?? ?? 8d ?? ?? 6a 01 6a 1c 51 50 6a 00 6a 00 ff 75 ?? ff 75 ?? ff 55 ?? 4b 75 e4 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}