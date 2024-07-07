
rule TrojanDownloader_O97M_Emotet_VP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.VP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {43 61 6c 6c 20 90 02 20 2e 20 5f 90 0c 02 00 43 72 65 61 74 65 28 90 02 20 2c 20 90 05 0f 06 41 2d 5a 61 2d 7a 2c 90 00 } //1
		$a_03_1 = {3d 20 4a 6f 69 6e 90 01 01 28 53 70 6c 69 74 28 90 02 20 2c 20 90 02 30 29 2c 20 90 02 25 29 90 00 } //1
		$a_03_2 = {2b 20 43 68 72 57 28 49 6e 74 28 77 64 4b 65 79 53 29 29 20 2b 20 90 02 20 2e 90 02 20 2e 54 61 67 20 2b 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}