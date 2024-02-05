
rule TrojanDownloader_O97M_Obfuse_GT{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.GT,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 65 74 20 90 02 35 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 90 02 35 28 31 29 29 90 00 } //01 00 
		$a_03_1 = {2e 43 72 65 61 74 65 20 90 02 35 28 30 29 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 90 00 } //01 00 
		$a_02_2 = {53 70 6c 69 74 28 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 90 02 08 29 2e 52 61 6e 67 65 28 90 02 08 29 2e 76 61 6c 75 65 2c 20 43 68 72 28 34 34 29 29 90 00 } //01 00 
		$a_02_3 = {53 70 6c 69 74 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 56 61 72 69 61 62 6c 65 73 28 90 02 16 29 2e 76 61 6c 75 65 2c 20 43 68 72 28 34 34 29 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}