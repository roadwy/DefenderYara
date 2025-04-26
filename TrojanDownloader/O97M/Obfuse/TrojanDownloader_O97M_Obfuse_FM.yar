
rule TrojanDownloader_O97M_Obfuse_FM{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.FM,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 69 6d 20 [0-19] 3a 20 53 65 74 20 [0-19] 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 [0-19] 28 31 29 29 3a 20 [0-19] 2e 43 72 65 61 74 65 20 [0-19] 28 30 29 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c } //2
		$a_03_1 = {53 70 6c 69 74 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 56 61 72 69 61 62 6c 65 73 28 [0-19] 29 2e 56 61 6c 75 65 2c 20 22 2c 22 29 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}