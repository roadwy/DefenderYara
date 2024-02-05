
rule Backdoor_Linux_ZHtrap_Do_xp{
	meta:
		description = "Backdoor:Linux/ZHtrap.Do!xp,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {47 45 54 20 2f 73 66 6b 6a 64 6b 66 64 6a 2e 74 78 74 } //01 00 
		$a_00_1 = {68 35 76 77 79 36 6f 33 32 73 64 63 73 61 35 78 75 72 64 65 33 35 64 71 77 35 73 66 33 63 64 73 6f 65 65 77 71 71 78 6d 68 6f 79 7a 73 76 61 72 34 75 36 6f 6f 65 61 64 2e 6f 6e 69 6f 6e } //01 00 
		$a_00_2 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 } //01 00 
		$a_00_3 = {2f 62 69 6e 2f 5a 6f 6e 65 53 65 63 } //01 00 
		$a_00_4 = {2f 70 72 6f 63 2f 63 70 75 69 6e 66 6f } //01 00 
		$a_00_5 = {74 65 6c 6e 65 74 61 64 6d 69 6e } //00 00 
	condition:
		any of ($a_*)
 
}