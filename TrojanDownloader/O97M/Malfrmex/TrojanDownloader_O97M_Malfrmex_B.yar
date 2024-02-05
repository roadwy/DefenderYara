
rule TrojanDownloader_O97M_Malfrmex_B{
	meta:
		description = "TrojanDownloader:O97M/Malfrmex.B,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 69 6d 65 20 3d 20 46 6f 72 6d 61 74 28 4e 6f 77 20 2b 20 54 69 6d 65 53 65 72 69 61 6c 28 30 2c 20 30 2c 20 32 34 29 2c 20 22 68 68 3a 6d 6d 22 29 } //01 00 
		$a_01_1 = {53 68 65 6c 6c 20 52 65 70 6c 61 63 65 28 41 70 70 32 2e 54 33 2e 54 65 78 74 2c 20 22 37 37 3a 37 37 22 2c 20 74 69 6d 65 29 } //01 00 
		$a_01_2 = {55 6e 6c 6f 61 64 20 4d 65 } //01 00 
		$a_01_3 = {43 61 6c 6c 42 79 4e 61 6d 65 20 41 70 70 31 2c 20 22 53 68 6f 77 22 2c 20 56 62 4d 65 74 68 6f 64 } //00 00 
	condition:
		any of ($a_*)
 
}