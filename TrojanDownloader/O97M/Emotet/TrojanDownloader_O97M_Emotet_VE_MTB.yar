
rule TrojanDownloader_O97M_Emotet_VE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.VE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {44 6f 20 57 68 69 6c 65 20 90 02 40 2e 20 5f 90 00 } //1
		$a_03_1 = {43 72 65 61 74 65 28 90 02 20 20 26 20 90 05 0f 06 41 2d 5a 61 2d 7a 2c 90 00 } //1
		$a_01_2 = {3d 20 43 68 72 57 28 65 77 72 72 63 20 2b 20 77 64 4b 65 79 50 20 2b 20 69 71 77 6a 6b 64 29 } //1 = ChrW(ewrrc + wdKeyP + iqwjkd)
		$a_01_3 = {3d 20 43 68 72 57 28 73 64 64 20 2b 20 77 64 4b 65 79 50 20 2b 20 63 78 7a 29 } //1 = ChrW(sdd + wdKeyP + cxz)
		$a_03_4 = {4a 6f 69 6e 28 90 02 20 2c 20 22 22 29 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}