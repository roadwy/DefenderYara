
rule TrojanDownloader_O97M_EncDoc_ESNG_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.ESNG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 22 26 22 74 74 70 22 26 22 73 3a 2f 2f 90 02 45 2e 90 02 15 2f 90 02 45 2e 70 22 26 22 6e 22 26 22 67 22 2c 22 90 00 } //1
		$a_03_1 = {68 22 26 22 74 74 70 22 26 22 73 3a 2f 2f 90 02 45 2e 90 02 15 2f 90 02 45 2e 70 22 26 22 6e 67 90 00 } //1
		$a_03_2 = {68 22 26 22 74 74 22 26 22 70 73 3a 2f 2f 90 02 45 2e 90 02 15 2f 90 02 45 2e 70 22 26 22 6e 67 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}