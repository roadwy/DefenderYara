
rule Backdoor_Linux_Mirai_BA_xp{
	meta:
		description = "Backdoor:Linux/Mirai.BA!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 } //01 00 
		$a_01_1 = {75 70 67 72 61 64 65 5f 68 61 6e 64 6c 65 2e 70 68 70 } //01 00 
		$a_01_2 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //01 00 
		$a_01_3 = {68 6c 4c 6a 7a 74 71 5a } //01 00 
		$a_01_4 = {63 68 6d 6f 64 2b 37 37 37 2b 77 67 65 74 62 69 6e } //01 00 
		$a_01_5 = {73 65 66 44 72 6f 70 } //01 00 
		$a_01_6 = {64 64 6f 73 5f 66 6c 6f 6f 64 5f 73 74 64 } //00 00 
	condition:
		any of ($a_*)
 
}