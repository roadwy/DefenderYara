
rule TrojanDownloader_O97M_Emotet_VW_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.VW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {43 61 6c 6c 20 90 02 20 2e 20 5f 90 0c 02 00 43 72 65 61 74 65 28 90 02 20 2e 90 02 30 20 2b 20 90 02 20 20 2b 20 90 02 20 2c 90 00 } //1
		$a_03_1 = {2b 20 43 68 72 57 28 90 02 20 2e 5a 6f 6f 6d 20 2b 90 00 } //1
		$a_03_2 = {3d 20 4a 6f 69 6e 28 90 02 18 2c 20 4e 6f 4c 69 6e 65 42 72 65 61 6b 41 66 74 65 72 29 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}