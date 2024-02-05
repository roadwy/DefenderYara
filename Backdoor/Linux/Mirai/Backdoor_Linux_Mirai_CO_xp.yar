
rule Backdoor_Linux_Mirai_CO_xp{
	meta:
		description = "Backdoor:Linux/Mirai.CO!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {00 79 90 12 21 64 96 12 e0 94 98 } //01 00 
		$a_00_1 = {dc 00 01 1e 3c 00 01 1e 0c 03 } //01 00 
		$a_00_2 = {20 01 a8 10 00 08 40 00 08 42 90 10 00 } //01 00 
		$a_00_3 = {10 21 00 40 00 24 ff 90 10 20 24 40 } //00 00 
	condition:
		any of ($a_*)
 
}