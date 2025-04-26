
rule TrojanDownloader_O97M_Remcos_GM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Remcos.GM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {53 65 74 20 [0-20] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 73 78 6d 6c 32 2e 44 4f 4d 44 6f 63 75 6d 65 6e 74 2e 33 2e 30 22 29 } //1
		$a_00_1 = {4c 6f 61 64 20 22 68 74 74 70 3a 2f 2f 31 38 35 2e 31 37 32 2e 31 31 30 2e 32 31 37 2f 72 6f 62 78 2f 72 65 6d 69 74 2e 6a 70 67 } //1 Load "http://185.172.110.217/robx/remit.jpg
		$a_00_2 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 6f 76 77 53 } //1 Attribute VB_Name = "ovwS
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}