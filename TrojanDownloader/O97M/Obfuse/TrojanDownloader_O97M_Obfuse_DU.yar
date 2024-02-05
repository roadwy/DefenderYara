
rule TrojanDownloader_O97M_Obfuse_DU{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.DU,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {47 65 74 4f 62 6a 65 63 74 28 90 02 10 2e 90 02 10 29 2e 43 72 65 61 74 65 20 90 02 10 20 2b 20 90 02 10 2e 90 02 10 20 2b 20 90 02 10 20 2b 90 00 } //01 00 
		$a_03_1 = {2e 53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 90 02 10 20 2b 90 00 } //01 00 
		$a_03_2 = {2b 20 4f 63 74 28 90 02 10 29 20 2f 20 90 10 09 00 20 2a 20 90 10 09 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}