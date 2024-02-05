
rule TrojanDownloader_O97M_Bartallex_Z{
	meta:
		description = "TrojanDownloader:O97M/Bartallex.Z,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {49 66 20 35 90 0f 05 00 20 3d 20 90 0f 06 00 20 2b 20 31 20 54 68 65 6e 20 45 6e 64 0d 0a 49 66 20 90 0f 04 00 20 3c 20 90 0f 02 00 20 54 68 65 6e 90 00 } //01 00 
		$a_02_1 = {49 66 20 4c 65 6e 28 22 90 1d 0f 00 22 29 20 3d 20 4c 65 6e 28 22 90 1d 0f 00 22 29 20 54 68 65 6e 0d 0a 90 0e 0f 00 4d 73 67 42 6f 78 20 28 22 45 72 72 6f 72 20 21 21 21 22 29 90 00 } //01 00 
		$a_02_2 = {53 68 65 6c 6c 20 90 12 0f 00 2e 90 12 0f 00 20 2b 20 90 12 0f 00 2e 90 12 0f 00 20 2b 20 90 12 0f 00 2e 90 12 0f 00 2c 20 76 62 48 69 64 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}