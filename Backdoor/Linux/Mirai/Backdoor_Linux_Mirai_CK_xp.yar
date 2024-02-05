
rule Backdoor_Linux_Mirai_CK_xp{
	meta:
		description = "Backdoor:Linux/Mirai.CK!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {72 6d 20 2d 72 66 20 2f 74 6d 70 2f 2a 20 2f 76 61 72 2f 2a 20 2f 76 61 72 2f 72 75 6e 2f 2a 20 2f 76 61 72 2f 74 6d 70 2f 2a } //01 00 
		$a_00_1 = {00 24 44 8d 94 00 00 28 21 8f 99 81 c4 00 00 00 00 03 20 f8 09 00 } //01 00 
		$a_00_2 = {24 42 db 38 ac 43 00 04 8f c3 } //01 00 
		$a_00_3 = {00 24 42 db 38 ac 43 00 08 24 02 00 03 af c2 00 08 } //01 00 
		$a_00_4 = {80 18 00 02 20 80 24 62 db 38 00 } //00 00 
	condition:
		any of ($a_*)
 
}