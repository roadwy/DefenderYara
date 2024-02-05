
rule Backdoor_Linux_Mirai_BH_xp{
	meta:
		description = "Backdoor:Linux/Mirai.BH!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 67 65 74 90 02 26 2f 74 6d 70 2f 73 6b 65 72 65 90 00 } //01 00 
		$a_01_1 = {2f 74 6d 70 2f 73 6b 65 72 65 20 64 75 63 6b 79 73 } //01 00 
		$a_01_2 = {53 45 52 56 5a 55 58 4f } //01 00 
		$a_01_3 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 } //01 00 
		$a_01_4 = {63 68 6d 6f 64 20 37 37 37 20 2a 20 2f 74 6d 70 2f 73 6b 65 72 65 } //00 00 
	condition:
		any of ($a_*)
 
}