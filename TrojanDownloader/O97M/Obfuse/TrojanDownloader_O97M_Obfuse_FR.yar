
rule TrojanDownloader_O97M_Obfuse_FR{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.FR,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 } //02 00 
		$a_03_1 = {2e 43 72 65 61 74 65 90 02 01 28 90 02 10 20 2b 20 90 02 25 20 2b 20 90 00 } //01 00 
		$a_03_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 10 29 90 00 } //01 00 
		$a_03_3 = {53 68 6f 77 57 69 6e 64 6f 77 90 02 01 20 3d 20 90 02 14 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}