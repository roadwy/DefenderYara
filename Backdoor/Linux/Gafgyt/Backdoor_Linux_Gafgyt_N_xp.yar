
rule Backdoor_Linux_Gafgyt_N_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.N!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 74 64 5f 66 6c 6f 6f 64 } //01 00 
		$a_00_1 = {76 73 65 61 74 74 61 63 6b } //01 00 
		$a_00_2 = {72 65 6d 6f 76 65 5f 6d 79 5f 61 74 74 61 63 6b 5f 70 69 64 } //01 00 
		$a_00_3 = {54 43 50 20 7c 20 54 43 50 20 46 6c 6f 6f 64 20 7c 20 74 63 70 20 3c 69 70 3e 20 3c 70 6f 72 74 3e 20 3c 73 65 63 6f 6e 64 28 73 29 3e 20 3c 66 6c 61 67 28 73 29 } //00 00 
		$a_00_4 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}