
rule TrojanDownloader_O97M_Emotet_RG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.RG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {2e 43 72 65 61 74 65 28 [0-20] 2c 20 [0-20] 2c 20 [0-20] 2c 20 [0-20] 29 } //1
		$a_03_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-20] 28 [0-20] 2e [0-45] 29 29 } //1
		$a_03_2 = {52 65 70 6c 61 63 65 [0-01] 28 [0-15] 2c 20 [0-15] 2e [0-15] 2c 20 [0-10] 28 22 } //1
		$a_03_3 = {36 22 2c 20 [0-12] 2e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}