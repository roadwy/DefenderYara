
rule TrojanDownloader_O97M_Obfuse_EI{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.EI,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {47 65 74 4f 62 6a 65 63 74 28 90 02 50 29 2e 43 72 65 61 74 65 20 90 02 10 2e 90 02 25 20 2b 20 90 00 } //10
		$a_03_1 = {53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 90 02 14 20 90 00 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}
rule TrojanDownloader_O97M_Obfuse_EI_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.EI,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {43 61 6c 6c 20 90 02 10 2e 90 02 10 28 53 74 72 43 6f 6e 76 28 90 02 10 2c 20 36 34 29 2c 20 30 29 90 00 } //1
		$a_03_1 = {46 6f 72 20 63 20 3d 20 41 73 63 28 22 41 22 29 20 54 6f 20 41 73 63 28 22 5a 22 29 3a 20 90 02 10 28 69 29 20 3d 20 63 3a 20 69 20 3d 20 69 20 2b 20 31 3a 20 4e 65 78 74 90 00 } //1
		$a_01_2 = {28 69 29 20 3d 20 41 73 63 28 22 2b 22 29 3a 20 69 20 3d 20 69 20 2b 20 31 } //1 (i) = Asc("+"): i = i + 1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}