
rule Backdoor_Linux_Mirai_AE_xp{
	meta:
		description = "Backdoor:Linux/Mirai.AE!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 52 4f 54 5f 45 58 45 43 } //01 00 
		$a_00_1 = {2f 70 72 6f 63 2f 73 65 6c 66 2f 65 78 65 37 } //01 00 
		$a_00_2 = {2f 70 72 6f 63 2f 73 65 6d 6e } //01 00 
		$a_00_3 = {61 6e 74 69 68 6f 6e 65 79 } //01 00 
		$a_00_4 = {63 68 6d 6f 6e 37 } //01 00 
		$a_00_5 = {6d 64 65 62 75 6e 67 2e 48 69 33 32 } //00 00 
		$a_00_6 = {5d 04 00 } //00 26 
	condition:
		any of ($a_*)
 
}