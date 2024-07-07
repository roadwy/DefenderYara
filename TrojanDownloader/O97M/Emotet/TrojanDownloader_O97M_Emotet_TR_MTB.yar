
rule TrojanDownloader_O97M_Emotet_TR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.TR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {44 6f 20 57 68 69 6c 65 20 90 02 20 2e 43 72 65 61 74 65 28 90 02 18 20 26 20 90 05 0f 06 41 2d 5a 61 2d 7a 2c 90 00 } //1
		$a_03_1 = {2b 20 43 68 72 57 28 77 64 4b 65 79 53 29 20 2b 20 90 02 20 2e 90 02 25 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 90 00 } //1
		$a_03_2 = {46 75 6e 63 74 69 6f 6e 20 90 02 20 28 29 90 02 08 44 6f 20 57 68 69 6c 65 90 00 } //1
		$a_01_3 = {54 61 67 29 29 2c } //1 Tag)),
		$a_01_4 = {73 68 6f 77 77 69 6e 64 6f 77 20 3d 20 46 61 6c 73 65 } //1 showwindow = False
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}