
rule TrojanDownloader_O97M_Obfuse_HJ{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.HJ,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {22 43 72 65 61 74 65 22 2c 20 56 62 4d 65 74 68 6f 64 2c 20 [0-38] 28 30 29 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c } //1
		$a_03_1 = {53 70 6c 69 74 28 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 [0-14] 29 2e 52 61 6e 67 65 28 [0-07] 29 2e 56 61 6c 75 65 2c 20 43 68 72 28 34 34 29 29 } //1
		$a_03_2 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 [0-38] 28 31 29 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}