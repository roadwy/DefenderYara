
rule TrojanDownloader_O97M_Obfuse_QP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.QP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 56 61 72 69 61 62 6c 65 73 28 22 [0-16] 22 29 2e 56 61 6c 75 65 } //1
		$a_03_1 = {26 20 52 69 67 68 74 28 4c 65 66 74 28 [0-18] 2c 20 [0-18] 29 2c 20 32 29 } //1
		$a_01_2 = {3d 20 43 68 72 28 30 } //1 = Chr(0
		$a_03_3 = {26 20 43 68 72 28 [0-14] 29 [0-42] 4e 65 78 74 } //1
		$a_03_4 = {3d 20 32 20 54 6f 20 4c 65 6e 28 [0-18] 29 20 53 74 65 70 20 32 } //1
		$a_03_5 = {53 68 65 6c 6c 20 [0-14] 28 [0-01] 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}