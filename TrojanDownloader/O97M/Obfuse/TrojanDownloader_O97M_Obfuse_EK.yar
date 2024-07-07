
rule TrojanDownloader_O97M_Obfuse_EK{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.EK,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 49 6e 6c 69 6e 65 53 68 61 70 65 73 28 90 02 04 20 2d 20 90 01 02 29 90 00 } //1
		$a_01_1 = {2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 2c 20 22 22 2c 20 22 22 2c 20 30 } //1 .AlternativeText, "", "", 0
		$a_03_2 = {47 65 74 4f 62 6a 65 63 74 28 22 6e 65 77 3a 22 20 26 20 90 02 15 29 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 25 20 5f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}