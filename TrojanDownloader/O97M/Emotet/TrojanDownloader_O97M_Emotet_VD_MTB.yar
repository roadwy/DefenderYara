
rule TrojanDownloader_O97M_Emotet_VD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.VD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {44 6f 20 57 68 69 6c 65 20 90 02 40 2e 20 5f 90 00 } //1
		$a_03_1 = {43 72 65 61 74 65 28 90 02 20 20 26 20 90 05 0f 06 41 2d 5a 61 2d 7a 2c 90 00 } //1
		$a_03_2 = {3d 20 53 70 6c 69 74 28 22 90 02 60 77 90 02 65 22 20 2b 20 90 00 } //1
		$a_03_3 = {44 65 62 75 67 2e 50 72 69 6e 74 20 22 50 75 74 69 6e 2e 56 2e 56 22 20 2b 20 90 02 04 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}