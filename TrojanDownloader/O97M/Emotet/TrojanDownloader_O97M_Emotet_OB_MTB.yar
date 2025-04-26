
rule TrojanDownloader_O97M_Emotet_OB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.OB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 [0-45] 28 [0-45] 28 22 [0-25] 77 [0-25] 69 [0-25] 6e } //1
		$a_03_1 = {2e 43 72 65 61 74 65 28 [0-45] 28 [0-45] 28 [0-45] 2e [0-45] 20 2b } //1
		$a_03_2 = {3d 20 52 65 70 6c 61 63 65 28 [0-35] 2c 20 [0-35] 2c 20 22 22 29 } //1
		$a_01_3 = {2c 20 4d 53 46 6f 72 6d 73 2c 20 54 65 78 74 42 6f 78 22 } //1 , MSForms, TextBox"
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}