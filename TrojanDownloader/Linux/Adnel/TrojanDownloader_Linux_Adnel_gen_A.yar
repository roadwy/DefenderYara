
rule TrojanDownloader_Linux_Adnel_gen_A{
	meta:
		description = "TrojanDownloader:Linux/Adnel.gen!A,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f } //01 00 
		$a_00_1 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 } //01 00 
		$a_00_2 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //01 00 
		$a_00_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 20 46 75 6c 6c 53 61 76 65 50 61 74 68 } //01 00 
		$a_00_4 = {49 66 20 52 75 6e 48 69 64 65 20 3d 20 46 61 6c 73 65 20 54 68 65 6e 3a 20 4f 43 58 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 47 41 54 45 2c 20 46 61 6c 73 65 } //00 00 
	condition:
		any of ($a_*)
 
}