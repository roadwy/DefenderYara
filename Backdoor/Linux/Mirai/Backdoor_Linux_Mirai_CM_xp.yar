
rule Backdoor_Linux_Mirai_CM_xp{
	meta:
		description = "Backdoor:Linux/Mirai.CM!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {00 c8 8d 44 24 21 28 00 00 c4 81 99 8f 00 00 00 00 09 f8 20 03 00 } //01 00 
		$a_00_1 = {00 d8 8d 42 24 18 00 c2 af 2b } //01 00 
		$a_00_2 = {80 82 8f 00 00 00 00 04 8e 44 24 21 28 00 00 c4 } //01 00 
		$a_00_3 = {00 18 8e 42 24 18 00 c2 af 05 } //00 00 
	condition:
		any of ($a_*)
 
}