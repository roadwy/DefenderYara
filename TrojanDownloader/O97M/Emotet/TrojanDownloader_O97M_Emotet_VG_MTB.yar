
rule TrojanDownloader_O97M_Emotet_VG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.VG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {44 6f 20 57 68 69 6c 65 20 [0-40] 2e 20 5f } //1
		$a_03_1 = {43 72 65 61 74 65 28 [0-20] 20 26 20 90 05 0f 06 41 2d 5a 61 2d 7a 2c } //1
		$a_01_2 = {3d 20 43 68 72 57 28 49 6e 74 28 77 64 4b 65 79 50 29 29 } //1 = ChrW(Int(wdKeyP))
		$a_03_3 = {3d 20 4a 6f 69 6e 28 [0-20] 2c 20 22 22 29 } //1
		$a_03_4 = {53 75 62 20 [0-20] 28 29 90 0c 02 00 44 65 62 75 67 2e 50 72 69 6e 74 20 22 50 75 74 69 6e 2e 56 2e 56 22 20 2b 20 67 67 90 0c 02 00 45 6e 64 20 53 75 62 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}