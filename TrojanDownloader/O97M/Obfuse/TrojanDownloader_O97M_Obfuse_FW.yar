
rule TrojanDownloader_O97M_Obfuse_FW{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.FW,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {44 69 6d 20 90 02 10 20 41 73 20 56 61 72 69 61 6e 74 3a 20 90 02 10 20 3d 20 53 70 6c 69 74 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 56 61 72 69 61 62 6c 65 73 28 90 02 16 29 2e 56 61 6c 75 65 2c 20 22 2c 22 29 90 00 } //02 00 
		$a_03_1 = {47 65 74 4f 62 6a 65 63 74 28 90 02 10 28 31 29 29 2e 43 72 65 61 74 65 20 90 02 10 28 30 29 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}