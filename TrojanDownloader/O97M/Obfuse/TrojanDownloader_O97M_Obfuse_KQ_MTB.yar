
rule TrojanDownloader_O97M_Obfuse_KQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.KQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c } //1 , Null, Null, Null
		$a_03_1 = {26 20 43 68 72 28 [0-45] 29 [0-02] 4e 65 78 74 } //1
		$a_03_2 = {53 68 65 65 74 73 28 [0-12] 29 2e 43 65 6c 6c 73 28 [0-08] 29 2e 56 61 6c 75 65 } //1
		$a_03_3 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 56 61 72 69 61 62 6c 65 73 28 [0-18] 29 2e 56 61 6c 75 65 } //1
		$a_03_4 = {3d 20 31 20 54 6f 20 4c 65 6e 28 [0-40] 29 20 53 74 65 70 20 32 [0-02] 44 69 6d } //1
		$a_03_5 = {3d 20 4d 69 64 28 [0-40] 2c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=5
 
}