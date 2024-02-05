
rule Backdoor_Linux_Mirai_CI_xp{
	meta:
		description = "Backdoor:Linux/Mirai.CI!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {00 06 00 46 10 08 00 63 24 01 00 08 25 fa ff 04 15 21 28 } //01 00 
		$a_00_1 = {34 21 20 20 02 09 f8 20 03 70 00 } //01 00 
		$a_00_2 = {08 00 45 24 42 00 43 24 1c 00 42 24 ff ff 63 30 } //01 00 
		$a_00_3 = {ff 00 4d 30 ff 00 66 30 ff 00 89 30 ff 00 ac } //01 00 
		$a_00_4 = {00 02 12 02 00 02 72 16 00 02 7a 15 } //00 00 
	condition:
		any of ($a_*)
 
}