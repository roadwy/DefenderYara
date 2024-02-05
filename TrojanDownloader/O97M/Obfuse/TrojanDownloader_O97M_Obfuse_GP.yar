
rule TrojanDownloader_O97M_Obfuse_GP{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.GP,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 10 20 2b 20 90 02 10 20 2b 20 90 02 10 29 20 5f 90 00 } //01 00 
		$a_03_1 = {2e 43 72 65 61 74 65 28 90 02 10 20 2b 90 00 } //01 00 
		$a_01_2 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 } //01 00 
		$a_01_3 = {53 68 6f 77 57 69 6e 64 6f 77 21 20 5f } //00 00 
	condition:
		any of ($a_*)
 
}