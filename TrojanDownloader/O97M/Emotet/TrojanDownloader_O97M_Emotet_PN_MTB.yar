
rule TrojanDownloader_O97M_Emotet_PN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {3d 20 22 57 [0-20] 69 [0-20] 6e [0-20] 33 [0-20] 32 [0-20] 5f [0-20] 50 [0-20] 72 [0-20] 6f [0-20] 63 [0-20] 65 [0-20] 73 [0-20] 73 [0-20] 22 } //1
		$a_03_1 = {2e 43 72 65 61 74 65 28 [0-25] 2c 20 [0-25] 2c 20 [0-25] 2c 20 [0-25] 29 } //1
		$a_03_2 = {2e 43 61 70 74 69 6f 6e 20 2b 20 [0-20] 2e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Emotet_PN_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {3d 20 22 70 [0-20] 57 [0-20] 69 [0-20] 6e [0-20] 33 [0-20] 32 [0-20] 5f 50 [0-20] 72 [0-20] 6f [0-20] 63 [0-20] 65 [0-20] 73 [0-20] 73 [0-20] 22 } //1
		$a_03_1 = {2e 43 72 65 61 74 65 28 [0-25] 2c 20 [0-25] 2c 20 [0-25] 2c 20 [0-25] 29 } //1
		$a_03_2 = {2e 43 61 70 74 69 6f 6e 20 2b 20 [0-20] 2e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}