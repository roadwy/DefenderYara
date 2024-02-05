
rule TrojanDownloader_O97M_Obfuse_ZC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.ZC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 43 68 72 28 90 02 03 20 2d 20 36 31 29 90 00 } //01 00 
		$a_01_1 = {2e 52 75 6e 28 44 5f 5f 6e 39 53 75 38 45 34 57 6a 5a 53 63 52 67 33 69 7a 41 44 59 58 32 77 5f } //01 00 
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 51 59 32 4f 4a 71 45 31 51 71 68 43 65 39 63 61 79 50 53 78 32 4d 6c 65 49 66 55 78 65 4e 6e 52 64 77 7a } //01 00 
		$a_01_3 = {52 6f 20 3d 20 52 6f 20 26 } //01 00 
		$a_03_4 = {6d 6b 5f 6c 6c 28 90 02 03 29 20 26 20 6d 6b 5f 6c 6c 28 90 02 03 29 20 26 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}