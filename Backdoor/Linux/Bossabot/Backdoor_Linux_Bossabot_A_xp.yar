
rule Backdoor_Linux_Bossabot_A_xp{
	meta:
		description = "Backdoor:Linux/Bossabot.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 43 41 4e 52 4e 44 32 } //01 00 
		$a_01_1 = {2f 74 6d 70 2f 52 65 56 31 31 31 32 } //01 00 
		$a_01_2 = {4e 4f 54 49 43 45 20 25 73 20 3a 53 44 } //01 00 
		$a_01_3 = {24 77 6f 70 20 3d 20 62 61 73 65 36 34 5f 64 65 63 6f 64 65 28 24 77 6f 70 29 } //01 00 
		$a_01_4 = {4e 4f 54 49 43 45 20 25 73 20 3a 72 6e 64 32 20 25 73 20 74 20 25 73 20 74 20 25 73 } //00 00 
	condition:
		any of ($a_*)
 
}