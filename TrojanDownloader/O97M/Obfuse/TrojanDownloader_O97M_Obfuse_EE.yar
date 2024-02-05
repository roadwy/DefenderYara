
rule TrojanDownloader_O97M_Obfuse_EE{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.EE,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {3d 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 49 6e 6c 69 6e 65 53 68 61 70 65 73 28 28 90 02 05 20 2d 90 02 05 29 20 2a 20 28 90 02 05 29 29 2e 20 5f 90 00 } //01 00 
		$a_01_1 = {41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 } //01 00 
		$a_03_2 = {2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 14 29 2e 52 75 6e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}