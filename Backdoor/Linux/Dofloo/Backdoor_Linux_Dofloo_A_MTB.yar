
rule Backdoor_Linux_Dofloo_A_MTB{
	meta:
		description = "Backdoor:Linux/Dofloo.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {44 4e 53 5f 46 6c 6f 6f 64 } //01 00 
		$a_00_1 = {55 44 50 5f 46 6c 6f 6f 64 } //01 00 
		$a_00_2 = {44 65 61 6c 77 69 74 68 44 44 6f 53 28 5f 4d 53 47 48 45 41 44 } //01 00 
		$a_00_3 = {73 65 64 20 2d 69 20 2d 65 20 27 2f 65 78 69 74 2f 64 27 20 2f 65 74 63 2f 72 63 2e 6c 6f 63 61 6c } //01 00 
		$a_00_4 = {73 65 64 20 2d 69 20 2d 65 20 27 32 20 69 2f 65 74 63 2f 25 73 20 72 65 62 6f 6f 74 27 20 2f 65 74 63 2f 72 63 2e 6c 6f 63 61 6c } //01 00 
		$a_00_5 = {64 64 6f 73 2e 74 66 } //00 00 
	condition:
		any of ($a_*)
 
}