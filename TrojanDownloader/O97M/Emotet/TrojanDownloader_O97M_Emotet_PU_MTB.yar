
rule TrojanDownloader_O97M_Emotet_PU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {69 6e 6d 6f 90 02 15 67 90 02 15 6d 90 02 15 74 90 02 15 73 90 02 15 3a 90 02 15 57 90 02 15 69 22 90 00 } //1
		$a_03_1 = {2e 43 72 65 61 74 65 28 90 02 25 2c 20 90 02 25 2c 20 90 02 25 2c 20 90 02 25 29 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}