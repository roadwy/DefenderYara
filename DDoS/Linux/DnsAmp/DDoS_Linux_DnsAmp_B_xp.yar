
rule DDoS_Linux_DnsAmp_B_xp{
	meta:
		description = "DDoS:Linux/DnsAmp.B!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {30 a0 b1 0f 00 00 ba 00 30 85 e0 01 30 43 e2 00 00 84 e0 02 c0 a0 e1 00 20 d3 e5 01 30 43 e2 2e 00 52 e3 00 c0 c0 05 00 20 c0 15 00 c0 a0 03 01 c0 8c 12 01 10 51 } //01 00 
		$a_00_1 = {11 01 30 a0 e3 00 30 c4 e5 10 40 bd e8 1e ff 2f e1 b8 f9 08 00 } //00 00 
	condition:
		any of ($a_*)
 
}