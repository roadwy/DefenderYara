
rule TrojanDownloader_O97M_Obfuse_DC{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.DC,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 06 00 00 "
		
	strings :
		$a_03_0 = {53 68 61 70 65 73 28 22 [0-20] 22 29 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 } //10
		$a_03_1 = {56 42 41 2e 49 6e 74 65 72 61 63 74 69 6f 6e 2e 53 68 65 6c 6c ?? 20 5f } //10
		$a_03_2 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 [0-10] 29 } //1
		$a_03_3 = {53 68 65 6c 6c 20 [0-20] 28 29 2c 20 4c 65 6e 28 [0-20] 28 29 29 } //1
		$a_03_4 = {53 68 65 6c 6c ?? 20 [0-20] 28 29 2c 20 4c 65 6e 28 [0-20] 28 29 29 } //1
		$a_03_5 = {53 68 65 6c 6c ?? 20 [0-10] 2c 20 76 62 48 69 64 65 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=11
 
}