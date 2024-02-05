
rule TrojanDownloader_O97M_Obfuse_FN{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.FN,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //02 00 
		$a_03_1 = {49 6e 74 65 72 61 63 74 69 6f 6e 2e 53 68 65 6c 6c 90 02 01 20 49 6e 6c 69 6e 65 53 68 61 70 65 73 28 90 02 20 29 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 2c 20 30 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}