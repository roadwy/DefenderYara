
rule Backdoor_Linux_Mirai_SZ_xp{
	meta:
		description = "Backdoor:Linux/Mirai.SZ!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 6b 69 6c 6c 61 6c 6c 62 6f 74 73 } //01 00 
		$a_00_1 = {79 6f 75 61 72 65 61 64 75 70 65 } //01 00 
		$a_00_2 = {2e 75 64 70 70 6c 61 69 6e } //01 00 
		$a_00_3 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 } //01 00 
		$a_00_4 = {2f 65 74 63 2f 64 72 6f 70 62 65 61 72 2f } //01 00 
		$a_00_5 = {2f 76 61 72 2f 53 6f 66 69 61 } //00 00 
		$a_00_6 = {5d 04 00 } //00 9b 
	condition:
		any of ($a_*)
 
}