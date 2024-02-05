
rule Backdoor_Linux_Mirai_I_xp{
	meta:
		description = "Backdoor:Linux/Mirai.I!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {62 6f 74 73 31 2e 66 69 72 65 77 61 6c 6c 61 31 33 33 37 2e 63 63 } //03 00 
		$a_00_1 = {2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 2f 78 33 38 2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 2f 78 33 38 2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 2f 78 33 38 2f 78 46 4a } //01 00 
		$a_00_2 = {73 63 61 6e 31 2e 66 69 72 65 77 61 6c 6c 61 31 33 33 37 2e 63 63 } //00 00 
		$a_00_3 = {8c 9e 00 00 } //04 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Linux_Mirai_I_xp_2{
	meta:
		description = "Backdoor:Linux/Mirai.I!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {66 33 32 34 61 73 63 2e 73 69 6e 69 73 74 65 72 6d 63 2e 78 79 7a } //01 00 
		$a_00_1 = {38 33 38 79 62 6a 38 6d 6e 66 69 } //01 00 
		$a_00_2 = {4e 69 47 47 65 52 36 39 78 64 20 } //01 00 
		$a_00_3 = {68 61 63 6b 74 68 65 77 6f 72 6c 64 31 33 33 37 } //01 00 
		$a_00_4 = {6c 76 72 76 75 70 39 77 30 7a 77 69 36 6e 75 71 66 30 6b 69 6c 75 6d 6c 6e 38 6f 78 35 76 67 76 66 33 32 34 61 73 64 2e 73 69 6e 69 73 74 65 72 6d 63 2e 78 79 7a } //01 00 
		$a_00_5 = {73 74 61 72 74 2d 73 68 65 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}