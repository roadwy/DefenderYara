
rule Backdoor_Linux_Mirai_AN_xp{
	meta:
		description = "Backdoor:Linux/Mirai.AN!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 65 74 63 2f 72 65 73 6f 6c 76 2e 63 6f 6e 66 } //01 00 
		$a_01_1 = {6f 6e 6d 6c 6b 6a 69 68 77 37 36 35 34 33 32 } //01 00 
		$a_01_2 = {64 66 65 33 63 68 6a 34 32 6f 69 77 35 6b 62 6e 37 6d 6c 61 } //01 00 
		$a_01_3 = {34 6d 77 36 68 66 6c 6e 6b 33 62 35 69 63 64 65 32 6a 6f 61 } //00 00 
	condition:
		any of ($a_*)
 
}