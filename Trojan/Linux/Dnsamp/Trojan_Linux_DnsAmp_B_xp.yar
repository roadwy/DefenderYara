
rule Trojan_Linux_DnsAmp_B_xp{
	meta:
		description = "Trojan:Linux/DnsAmp.B!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {44 4e 53 5f 46 6c 6f 6f 64 } //01 00 
		$a_00_1 = {00 20 af b1 00 1c af b0 00 18 af bc 00 10 8f 91 80 1c 00 00 } //01 00 
		$a_00_2 = {67 65 74 68 6f 73 74 62 79 6e 61 6d 65 } //01 00 
		$a_00_3 = {14 24 84 a0 00 10 40 00 05 24 a5 07 b4 03 20 f8 09 00 } //01 00 
		$a_00_4 = {44 65 61 6c 77 69 74 68 44 44 6f 53 } //00 00 
	condition:
		any of ($a_*)
 
}