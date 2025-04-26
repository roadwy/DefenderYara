
rule TrojanDownloader_O97M_Emotet_PS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {3d 20 22 77 [0-15] 69 [0-15] 6e [0-15] 6d [0-15] 67 [0-15] 6d [0-15] 74 [0-15] 73 3a [0-15] 57 [0-15] 69 [0-15] 22 } //1
		$a_03_1 = {2e 43 72 65 61 74 65 28 [0-25] 2c 20 [0-25] 2c 20 [0-25] 2c 20 [0-25] 29 } //1
		$a_03_2 = {2e 43 61 70 74 69 6f 6e 20 2b 20 [0-20] 2e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Emotet_PS_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {3d 20 22 61 [0-15] 77 [0-15] 69 [0-15] 6e [0-15] 6d [0-15] 67 [0-15] 6d [0-15] 74 [0-15] 73 [0-15] 3a [0-15] 57 [0-15] 69 [0-15] 22 } //1
		$a_03_1 = {2e 43 72 65 61 74 65 28 [0-25] 2c 20 [0-25] 2c 20 [0-25] 2c 20 [0-25] 29 } //1
		$a_03_2 = {2e 43 61 70 74 69 6f 6e 20 2b 20 [0-20] 2e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}