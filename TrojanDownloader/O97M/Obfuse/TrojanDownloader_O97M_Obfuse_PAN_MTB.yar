
rule TrojanDownloader_O97M_Obfuse_PAN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PAN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {53 75 62 20 [0-10] 28 [0-10] 2c 20 4f 70 74 69 6f 6e 61 6c 20 42 79 56 61 6c 20 [0-10] 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 73 79 73 74 65 6d 6f 62 6a 65 63 74 22 29 } //1
		$a_01_1 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //1 Sub AutoOpen()
		$a_03_2 = {29 2e 65 78 65 63 20 28 [0-10] 28 [0-10] 29 20 26 20 22 20 22 20 26 20 65 76 57 6e 55 20 26 20 22 2c 53 68 6f 77 44 69 61 6c 6f 67 41 20 2d 72 22 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}