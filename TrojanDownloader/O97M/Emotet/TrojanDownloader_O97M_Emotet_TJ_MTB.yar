
rule TrojanDownloader_O97M_Emotet_TJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.TJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {44 6f 20 57 68 69 6c 65 20 [0-18] 2e 43 72 65 61 74 65 28 [0-18] 20 26 20 90 05 0f 06 41 2d 5a 61 2d 7a 2c } //1
		$a_03_1 = {2c 20 4d 53 46 6f 72 6d 73 2c 20 54 65 78 74 42 6f 78 22 90 0c 02 00 50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 } //1
		$a_03_2 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 2b 20 90 05 0f 06 41 2d 5a 61 2d 7a 2e } //1
		$a_01_3 = {2e 54 61 67 } //1 .Tag
		$a_01_4 = {4c 6f 6f 70 } //1 Loop
		$a_03_5 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 90 05 0f 06 41 2d 5a 61 2d 7a 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}