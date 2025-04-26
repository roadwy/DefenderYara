
rule TrojanDownloader_O97M_Emotet_SU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {44 6f 20 57 68 69 6c 65 20 [0-15] 2e 43 72 65 61 74 65 28 4e 75 6c 6c 20 26 20 90 05 0f 06 41 2d 5a 61 2d 7a 2c } //1
		$a_03_1 = {3d 20 22 77 [0-15] 69 [0-15] 6e [0-15] 6d [0-15] 67 [0-15] 6d [0-15] 74 [0-15] 73 [0-15] 3a } //1
		$a_03_2 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 2b 20 90 05 0f 06 41 2d 5a 61 2d 7a 2e } //1
		$a_03_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 05 0f 06 41 2d 5a 61 2d 7a 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}