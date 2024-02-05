
rule TrojanDownloader_O97M_Obfuse_EY{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.EY,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 75 74 6f 6f 70 65 6e 28 20 5f } //01 00 
		$a_01_1 = {53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 76 62 46 61 6c 73 65 20 2d 20 76 62 46 61 6c 73 65 } //01 00 
		$a_01_2 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 43 53 74 72 28 22 57 69 6e 6d 67 6d 74 73 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 53 22 29 29 } //01 00 
		$a_01_3 = {47 65 74 4f 62 6a 65 2e 43 72 65 61 20 3d 20 } //00 00 
	condition:
		any of ($a_*)
 
}