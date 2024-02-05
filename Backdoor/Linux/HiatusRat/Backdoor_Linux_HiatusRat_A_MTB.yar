
rule Backdoor_Linux_HiatusRat_A_MTB{
	meta:
		description = "Backdoor:Linux/HiatusRat.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 63 70 5f 66 6f 72 77 61 72 64 } //01 00 
		$a_01_1 = {65 78 65 63 75 74 6f 72 } //01 00 
		$a_01_2 = {75 70 6c 6f 61 64 3f 75 75 69 64 3d } //01 00 
		$a_01_3 = {66 6f 72 77 61 72 64 65 72 20 65 78 69 73 74 } //01 00 
		$a_01_4 = {2f 6d 61 73 74 65 72 2f 41 70 69 2f 61 63 74 69 76 65 } //01 00 
		$a_01_5 = {2f 6d 61 73 74 65 72 2f 41 70 69 2f 72 65 70 6c 79 } //00 00 
	condition:
		any of ($a_*)
 
}