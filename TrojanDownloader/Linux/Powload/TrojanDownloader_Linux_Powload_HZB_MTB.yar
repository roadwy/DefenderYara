
rule TrojanDownloader_Linux_Powload_HZB_MTB{
	meta:
		description = "TrojanDownloader:Linux/Powload.HZB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 6f 66 66 69 63 65 2d 63 6c 65 61 6e 65 72 2d 69 6e 64 65 78 2e 63 6f 6d 2f [0-20] 7c 7c 7c 6d 73 78 6d 6c 32 2e 78 6d 6c 68 74 74 70 } //1
		$a_03_1 = {2e 4f 70 65 6e 20 22 67 65 74 22 2c 20 [0-10] 2c 20 46 61 6c 73 65 } //1
		$a_03_2 = {53 65 74 20 [0-10] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}