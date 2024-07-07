
rule DDoS_Linux_Ropiv_A_xp{
	meta:
		description = "DDoS:Linux/Ropiv.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 6e 6d 70 73 63 61 6e 2e 63 } //1 snmpscan.c
		$a_01_1 = {64 69 73 74 6f 72 74 65 64 58 5f 53 4e 4d 50 53 43 41 4e } //1 distortedX_SNMPSCAN
		$a_01_2 = {56 79 70 6f 72 27 73 20 53 4e 4d 50 } //1 Vypor's SNMP
		$a_01_3 = {64 2e 61 2e 74 2e 61 2e 62 2e 72 2e 65 2e 61 2e 6b } //1 d.a.t.a.b.r.e.a.k
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}