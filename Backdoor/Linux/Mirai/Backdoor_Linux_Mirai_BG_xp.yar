
rule Backdoor_Linux_Mirai_BG_xp{
	meta:
		description = "Backdoor:Linux/Mirai.BG!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 6d 68 64 69 70 63 } //01 00 
		$a_01_1 = {75 64 70 70 6c 61 69 6e } //01 00 
		$a_01_2 = {6b 69 6c 6c 70 72 6f 63 } //01 00 
		$a_01_3 = {73 6d 63 61 64 6d 69 6e } //01 00 
		$a_01_4 = {74 73 67 6f 69 6e 67 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}