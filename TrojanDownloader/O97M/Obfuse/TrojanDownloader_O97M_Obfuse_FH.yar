
rule TrojanDownloader_O97M_Obfuse_FH{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.FH,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //02 00 
		$a_03_1 = {43 61 6c 6c 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 14 2e 54 65 78 74 29 2e 52 75 6e 90 02 01 28 20 5f 90 00 } //01 00 
		$a_01_2 = {54 65 78 74 2c 20 5f } //00 00 
	condition:
		any of ($a_*)
 
}