
rule TrojanDownloader_O97M_Kodviron_B{
	meta:
		description = "TrojanDownloader:O97M/Kodviron.B,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 0d 0a } //01 00 
		$a_01_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 6d 73 78 6d 6c 32 2e 78 6d 6c 68 74 74 70 22 29 } //01 00 
		$a_01_2 = {45 6e 76 69 72 6f 6e 28 68 65 78 74 6f 73 74 72 69 6e 67 28 43 68 72 24 28 35 33 29 20 26 20 43 68 72 24 28 35 32 29 20 26 20 43 68 72 24 28 35 32 29 20 26 20 43 68 72 24 28 35 33 29 20 26 20 43 68 72 24 28 } //00 00 
	condition:
		any of ($a_*)
 
}