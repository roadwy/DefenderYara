
rule TrojanDownloader_O97M_Emotet_UF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.UF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {44 6f 20 57 68 69 6c 65 20 [0-40] 2e 20 5f } //1
		$a_03_1 = {43 72 65 61 74 65 28 [0-20] 20 26 20 90 05 0f 06 41 2d 5a 61 2d 7a 2c } //1
		$a_03_2 = {2b 20 43 68 72 57 28 77 64 4b 65 79 53 29 20 2b 20 22 [0-30] 77 [0-30] 69 [0-30] 6e [0-30] 33 [0-30] 32 [0-30] 5f [0-30] 22 } //1
		$a_01_3 = {43 68 72 57 28 77 64 4b 65 79 50 29 } //1 ChrW(wdKeyP)
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}