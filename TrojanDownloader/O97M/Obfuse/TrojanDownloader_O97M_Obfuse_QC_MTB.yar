
rule TrojanDownloader_O97M_Obfuse_QC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.QC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {53 68 65 65 74 73 28 22 [0-14] 22 29 2e 43 65 6c 6c 73 28 [0-14] 29 2e 56 61 6c 75 65 2c } //1
		$a_03_1 = {2e 43 72 65 61 74 65 20 [0-14] 2c 20 [0-30] 2c 20 4e 75 6c 6c } //1
		$a_03_2 = {26 20 43 68 72 28 43 4c 6e 67 28 [0-14] 20 26 20 4d 69 64 28 [0-14] 2c 20 [0-18] 29 29 20 2d 20 [0-02] 29 [0-42] 4e 65 78 74 } //1
		$a_03_3 = {3d 20 31 20 54 6f 20 4c 65 6e 28 [0-14] 29 20 53 74 65 70 20 32 } //1
		$a_01_4 = {3d 20 22 22 } //1 = ""
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}