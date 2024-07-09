
rule TrojanDownloader_O97M_Obfuse_WX_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.WX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {31 37 38 2e 36 32 2e 34 31 2e 33 37 3a 34 34 34 34 2f [0-09] 2e 65 78 65 90 0a 24 00 68 74 74 70 3a 2f 2f } //1
		$a_03_1 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 22 [0-09] 2e 65 78 65 22 } //1
		$a_03_2 = {53 68 65 6c 6c 20 28 22 63 6d 64 20 2f 63 20 44 3a 5c 55 73 65 72 73 5c [0-14] 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-09] 2e 65 78 65 20 22 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}