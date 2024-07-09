
rule TrojanDownloader_O97M_Emotet_SR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {44 6f 20 57 68 69 6c 65 20 [0-12] 2e 43 72 65 61 74 65 28 4e 75 6c 6c 20 26 20 90 05 0f 06 41 2d 5a 61 2d 7a 2c } //1
		$a_03_1 = {2b 20 22 53 [0-15] 54 [0-20] 41 [0-14] 52 [0-15] 54 [0-20] 55 22 } //1
		$a_03_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 28 90 05 0f 06 41 2d 5a 61 2d 7a 29 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}