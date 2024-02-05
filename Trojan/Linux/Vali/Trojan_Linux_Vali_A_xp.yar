
rule Trojan_Linux_Vali_A_xp{
	meta:
		description = "Trojan:Linux/Vali.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 74 6d 70 2f 2e 76 61 6c 69 } //01 00 
		$a_00_1 = {4d 61 6c 69 63 69 6f 75 73 20 63 6f 64 65 2e 2e 2e } //01 00 
		$a_00_2 = {2a 2a 2a 49 6e 66 65 63 74 65 64 20 25 73 2e } //01 00 
		$a_00_3 = {56 61 6c 69 20 68 65 72 65 2e 2e 2e } //00 00 
		$a_00_4 = {5d 04 00 } //00 de 
	condition:
		any of ($a_*)
 
}