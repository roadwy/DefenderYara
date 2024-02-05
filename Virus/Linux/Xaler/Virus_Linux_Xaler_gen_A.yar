
rule Virus_Linux_Xaler_gen_A{
	meta:
		description = "Virus:Linux/Xaler.gen!A,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {4e 6f 72 6d 61 6c 54 65 6d 70 6c 61 74 65 2e 56 42 50 72 6f 6a 65 63 74 2e 76 62 63 6f 6d 70 6f 6e 65 6e 74 73 2e 49 74 65 6d 28 22 54 68 69 73 44 6f 63 75 6d 65 6e 74 22 29 2e 43 6f 64 65 4d 6f 64 75 6c 65 2e 49 6e 73 65 72 74 4c 69 6e 65 73 20 31 2c 20 6b 65 69 6d 65 6e 6f } //01 00 
		$a_00_1 = {49 6e 53 74 72 28 31 2c 20 6b 65 69 6d 65 6e 6f 2c 20 22 27 52 45 4c 41 58 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}