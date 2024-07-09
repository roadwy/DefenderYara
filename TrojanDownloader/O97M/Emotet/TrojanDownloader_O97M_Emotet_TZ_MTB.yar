
rule TrojanDownloader_O97M_Emotet_TZ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.TZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {44 6f 20 57 68 69 6c 65 20 [0-20] 2e 20 5f 90 0c 02 00 43 72 65 61 74 65 28 [0-20] 20 26 20 90 05 0f 06 41 2d 5a 61 2d 7a 2c } //1
		$a_03_1 = {3d 20 53 70 6c 69 74 28 22 [0-60] 77 [0-60] 22 20 2b 20 64 2c 20 45 29 } //1
		$a_03_2 = {4a 6f 69 6e 28 [0-20] 2c 20 22 22 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}