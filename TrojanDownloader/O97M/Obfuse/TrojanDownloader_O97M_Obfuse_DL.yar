
rule TrojanDownloader_O97M_Obfuse_DL{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.DL,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 90 02 10 29 90 00 } //01 00 
		$a_03_1 = {49 6e 74 65 72 61 63 74 69 6f 6e 2e 53 68 65 6c 6c 90 01 01 20 5f 90 00 } //01 00 
		$a_01_2 = {2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 2c 20 76 62 48 69 64 65 } //00 00 
	condition:
		any of ($a_*)
 
}