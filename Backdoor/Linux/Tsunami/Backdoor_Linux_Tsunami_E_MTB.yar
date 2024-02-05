
rule Backdoor_Linux_Tsunami_E_MTB{
	meta:
		description = "Backdoor:Linux/Tsunami.E!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {4e 4f 54 49 43 45 20 25 73 20 3a 48 54 54 50 20 46 6c 6f 6f 64 20 53 74 61 72 74 69 6e 67 20 6f 6e 20 25 73 } //01 00 
		$a_00_1 = {25 73 20 3a 52 54 43 50 20 46 6c 6f 6f 64 } //01 00 
		$a_00_2 = {52 61 77 55 44 50 20 46 6c 6f 6f 64 20 41 67 61 69 6e 73 74 20 25 73 20 46 69 6e 69 73 68 65 64 } //01 00 
		$a_00_3 = {52 65 6d 6f 76 65 64 20 41 6c 6c 20 53 70 6f 6f 66 73 } //01 00 
		$a_00_4 = {72 74 63 70 5f 61 74 74 61 63 6b } //00 00 
	condition:
		any of ($a_*)
 
}