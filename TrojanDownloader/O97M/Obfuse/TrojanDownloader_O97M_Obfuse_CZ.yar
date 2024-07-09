
rule TrojanDownloader_O97M_Obfuse_CZ{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.CZ,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {53 68 65 6c 6c 28 [0-70] 2c 20 76 62 48 69 64 65 29 } //1
		$a_03_1 = {3d 20 49 6e 53 74 72 28 [0-20] 28 41 72 72 61 79 28 } //1
		$a_03_2 = {3d 20 4c 54 72 69 6d 28 22 [0-20] 22 29 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}