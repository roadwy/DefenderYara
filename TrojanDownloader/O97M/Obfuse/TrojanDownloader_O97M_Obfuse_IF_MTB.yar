
rule TrojanDownloader_O97M_Obfuse_IF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.IF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {53 68 65 6c 6c 20 28 [0-04] 29 } //1
		$a_03_1 = {46 6f 72 20 [0-09] 20 3d 20 31 20 54 6f 20 4c 65 6e 28 [0-09] 29 } //1
		$a_03_2 = {4d 69 64 28 [0-09] 2c 20 [0-09] 2c 20 31 29 20 3d 20 43 68 72 28 41 73 63 28 4d 69 64 28 [0-09] 2c 20 [0-09] 2c 20 31 29 29 20 2d 20 [0-09] 29 } //1
		$a_01_3 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 } //1 Sub Workbook_Open()
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}