
rule TrojanDownloader_O97M_Emotet_QI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.QI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {2e 43 72 65 61 74 65 28 [0-45] 2c 20 [0-25] 2c 20 [0-25] 2c 20 [0-25] 29 } //1
		$a_03_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-15] 28 [0-25] 28 [0-02] 29 29 29 } //1
		$a_03_2 = {3d 20 52 65 70 6c 61 63 65 28 [0-20] 2c 20 [0-20] 2c 20 22 22 29 } //1
		$a_03_3 = {4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 [0-07] 44 69 6d } //1
		$a_01_4 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 } //1 Sub autoopen()
		$a_01_5 = {2e 53 68 6f 77 57 69 6e 64 6f 77 20 3d } //1 .ShowWindow =
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}