
rule Backdoor_Linux_Tsunami_O_xp{
	meta:
		description = "Backdoor:Linux/Tsunami.O!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 45 54 53 50 4f 4f 46 53 } //01 00 
		$a_01_1 = {48 54 54 50 46 4c 4f 4f 44 } //01 00 
		$a_01_2 = {25 73 20 3a 52 65 6d 6f 76 65 64 20 61 6c 6c 20 73 70 6f 6f 66 73 } //01 00 
		$a_01_3 = {50 52 49 56 4d 53 47 20 25 73 20 3a 53 70 6f 6f 66 73 } //01 00 
		$a_01_4 = {42 65 73 6c 69 73 74 42 6f 74 } //01 00 
		$a_01_5 = {6d 78 62 6f 74 2f 31 2e 30 } //00 00 
	condition:
		any of ($a_*)
 
}