
rule TrojanDownloader_O97M_Emotet_SW_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {2e 43 72 65 61 74 65 28 4e 75 6c 6c 20 26 20 90 05 0f 06 41 2d 5a 61 2d 7a 2c } //1
		$a_03_1 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 2b 20 90 05 0f 06 41 2d 5a 61 2d 7a 2e } //1
		$a_03_2 = {3d 20 4a 6f 69 6e 28 53 70 6c 69 74 28 22 77 [0-15] 69 [0-15] 6e [0-15] 6d [0-15] 67 [0-15] 6d [0-15] 74 [0-15] 73 [0-15] 3a 57 [0-15] 69 [0-15] 6e [0-15] 33 [0-15] 32 [0-15] 5f [0-15] 22 2c 20 22 [0-15] 22 29 2c 20 22 22 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}