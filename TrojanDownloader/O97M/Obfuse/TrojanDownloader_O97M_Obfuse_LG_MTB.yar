
rule TrojanDownloader_O97M_Obfuse_LG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.LG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {22 76 65 72 69 6e 73 74 65 72 65 2e 78 6c 73 22 } //1 "verinstere.xls"
		$a_01_1 = {26 20 22 2e 68 74 6d 22 2c 20 5f } //1 & ".htm", _
		$a_01_2 = {28 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 29 } //1 (Environ("TEMP"))
		$a_03_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-07] 2e 54 61 67 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}