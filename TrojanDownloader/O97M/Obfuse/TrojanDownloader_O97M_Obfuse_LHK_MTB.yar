
rule TrojanDownloader_O97M_Obfuse_LHK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.LHK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 53 74 72 43 6f 6e 76 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 56 61 72 69 61 62 6c 65 73 28 22 90 02 20 22 29 2e 56 61 6c 75 65 2c 20 90 02 03 29 90 00 } //01 00 
		$a_03_1 = {3d 20 53 74 72 43 6f 6e 76 28 53 68 65 65 74 73 28 22 90 02 10 22 29 2e 43 65 6c 6c 73 28 90 02 03 2c 20 90 02 02 29 2e 56 61 6c 75 65 2c 20 90 02 03 29 90 00 } //01 00 
		$a_03_2 = {3d 20 54 72 75 65 90 0c 02 00 4f 70 74 69 6f 6e 20 45 78 70 6c 69 63 69 74 90 00 } //01 00 
		$a_01_3 = {47 6f 54 6f 20 } //01 00  GoTo 
		$a_01_4 = {53 68 65 6c 6c 20 } //00 00  Shell 
	condition:
		any of ($a_*)
 
}