
rule TrojanDownloader_O97M_Obfuse_EL{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.EL,SIGNATURE_TYPE_MACROHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {2e 43 72 65 61 74 65 20 90 02 10 2e 90 02 25 20 2b 20 90 00 } //01 00 
		$a_03_1 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 90 02 40 29 90 00 } //01 00 
		$a_03_2 = {53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 90 02 14 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}