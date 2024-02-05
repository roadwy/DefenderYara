
rule Virus_Linux_Ostrich_gen_A{
	meta:
		description = "Virus:Linux/Ostrich.gen!A,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 56 42 50 72 6f 6a 65 63 74 2e 56 42 43 6f 6d 70 6f 6e 65 6e 74 73 2e 49 74 65 6d 28 26 4f 31 29 2e 43 6f 64 65 4d 6f 64 75 6c 65 } //01 00 
		$a_01_1 = {3a 20 44 6f 20 57 68 69 6c 65 20 2e 43 6f 75 6e 74 4f 66 4c 69 6e 65 73 20 3e 20 26 4f 30 3a 20 2e 44 65 6c 65 74 65 4c 69 6e 65 73 20 31 3a 20 4c 6f 6f 70 3a 20 45 6e 64 20 57 69 74 68 } //01 00 
		$a_01_2 = {2c 20 26 4f 31 2c 20 2e 43 6f 75 6e 74 4f 66 4c 69 6e 65 73 2c 20 31 2c 20 46 61 6c 73 65 2c 20 46 61 6c 73 65 2c 20 46 61 6c 73 65 29 20 54 68 65 6e } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}