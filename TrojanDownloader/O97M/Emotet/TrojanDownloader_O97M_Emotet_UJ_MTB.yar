
rule TrojanDownloader_O97M_Emotet_UJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.UJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {44 6f 20 57 68 69 6c 65 20 [0-40] 2e 20 5f } //1
		$a_03_1 = {43 72 65 61 74 65 28 [0-20] 20 26 20 90 05 0f 06 41 2d 5a 61 2d 7a 2c } //1
		$a_03_2 = {2e 47 72 6f 75 70 4e 61 6d 65 [0-20] 20 3d 20 53 70 6c 69 74 28 [0-20] 20 2b 20 43 56 61 72 28 54 72 69 6d 28 [0-10] 29 29 2c } //1
		$a_03_3 = {46 75 6e 63 74 69 6f 6e 20 [0-20] 28 29 [0-08] 46 6f 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}