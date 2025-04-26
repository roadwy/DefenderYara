
rule TrojanDownloader_O97M_Obfuse_KRN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.KRN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {2e 4f 70 65 6e 20 22 67 65 74 22 2c 20 [0-15] 28 22 71 [0-64] 6e 22 29 2c 20 46 61 6c 73 65 } //1
		$a_03_1 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 [0-0c] 2c 20 [0-0c] 20 2b 20 } //1
		$a_03_2 = {4d 73 67 42 6f 78 20 22 [0-15] 22 } //1
		$a_01_3 = {26 20 22 22 20 3d 20 22 22 20 54 68 65 6e 20 45 78 69 74 20 46 75 6e 63 74 69 6f 6e } //1 & "" = "" Then Exit Function
		$a_01_4 = {3d 20 43 68 72 28 35 30 29 20 2b 20 43 68 72 28 34 38 29 20 2b 20 43 68 72 28 34 38 29 } //1 = Chr(50) + Chr(48) + Chr(48)
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}