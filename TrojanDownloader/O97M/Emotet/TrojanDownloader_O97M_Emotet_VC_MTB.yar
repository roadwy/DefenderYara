
rule TrojanDownloader_O97M_Emotet_VC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.VC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {44 6f 20 57 68 69 6c 65 20 [0-40] 2e 20 5f } //1
		$a_03_1 = {43 72 65 61 74 65 28 [0-20] 20 26 20 90 05 0f 06 41 2d 5a 61 2d 7a 2c } //1
		$a_03_2 = {3d 20 53 70 6c 69 74 28 22 [0-60] 77 [0-60] 22 20 2b 20 65 65 20 2b 20 64 66 65 2c 20 69 64 73 66 65 65 65 29 } //1
		$a_01_3 = {3d 20 53 70 6c 69 74 28 73 64 64 64 64 2c 20 77 65 66 66 29 } //1 = Split(sdddd, weff)
		$a_03_4 = {4a 6f 69 6e 28 [0-20] 2c 20 22 22 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}