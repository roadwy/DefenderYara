
rule TrojanDownloader_O97M_Emotet_PU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {69 6e 6d 6f [0-15] 67 [0-15] 6d [0-15] 74 [0-15] 73 [0-15] 3a [0-15] 57 [0-15] 69 22 } //1
		$a_03_1 = {2e 43 72 65 61 74 65 28 [0-25] 2c 20 [0-25] 2c 20 [0-25] 2c 20 [0-25] 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}