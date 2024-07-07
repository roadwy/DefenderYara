
rule TrojanDownloader_O97M_Emotet_UR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.UR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {44 6f 20 57 68 69 6c 65 20 90 02 40 2e 20 5f 90 00 } //1
		$a_03_1 = {43 72 65 61 74 65 28 90 02 20 20 26 20 90 05 0f 06 41 2d 5a 61 2d 7a 2c 90 00 } //1
		$a_03_2 = {4e 65 78 74 90 02 20 2e 20 5f 90 0c 02 00 73 68 6f 77 77 69 6e 64 6f 77 20 3d 20 46 61 6c 73 65 90 00 } //1
		$a_01_3 = {3d 20 43 68 72 57 28 4c 4b 20 2b 20 77 64 4b 65 79 50 20 2b 20 50 4f 29 } //1 = ChrW(LK + wdKeyP + PO)
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}