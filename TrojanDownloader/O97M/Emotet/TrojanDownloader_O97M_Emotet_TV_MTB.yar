
rule TrojanDownloader_O97M_Emotet_TV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.TV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {44 6f 20 57 68 69 6c 65 20 90 02 20 2e 43 72 65 61 74 65 28 90 02 20 20 26 20 90 05 0f 06 41 2d 5a 61 2d 7a 2c 90 00 } //1
		$a_03_1 = {3d 20 53 70 6c 69 74 28 22 90 02 60 77 22 20 2b 20 77 65 6e 2c 20 73 6b 69 29 90 00 } //1
		$a_01_2 = {2e 54 61 67 } //1 .Tag
		$a_03_3 = {4a 6f 69 6e 28 90 02 20 2c 20 22 22 29 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}