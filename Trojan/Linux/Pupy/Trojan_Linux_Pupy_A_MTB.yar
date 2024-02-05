
rule Trojan_Linux_Pupy_A_MTB{
	meta:
		description = "Trojan:Linux/Pupy.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 75 70 79 } //01 00 
		$a_03_1 = {8b bc 24 18 21 00 00 48 8b 74 24 20 48 8d 15 92 93 00 00 e8 90 02 05 3c ff 75 8b 48 8d 3d 8c 93 00 00 48 8d ac 24 40 10 00 00 e8 90 02 05 48 8d 35 7c 93 00 00 48 89 ef e8 90 02 05 48 85 c0 74 1d e8 90 02 05 48 8d 15 01 8d 00 00 89 c1 be 00 10 00 00 48 89 ef 31 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}