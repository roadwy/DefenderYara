
rule DDoS_Linux_Silly_A_xp{
	meta:
		description = "DDoS:Linux/Silly.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 6e 67 72 79 20 56 61 64 69 6d 73 } //1 angry Vadims
		$a_01_1 = {53 79 6e 74 61 78 3a 20 25 73 20 3c 68 6f 73 74 3e 20 3c 70 6f 72 74 3e 20 3c 73 70 6f 6f 66 3e } //1 Syntax: %s <host> <port> <spoof>
		$a_01_2 = {76 61 64 69 6d 2e 63 } //1 vadim.c
		$a_01_3 = {70 6f 72 74 20 25 64 20 73 70 6f 6f 66 65 64 20 61 73 20 25 73 } //1 port %d spoofed as %s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}