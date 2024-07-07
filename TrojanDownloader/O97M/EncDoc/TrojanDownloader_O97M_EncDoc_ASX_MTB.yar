
rule TrojanDownloader_O97M_EncDoc_ASX_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.ASX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 3a 2f 2f 90 02 40 2e 90 02 08 2f 90 02 20 2f 90 02 12 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c 90 00 } //1
		$a_03_1 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 2f 2f 90 02 40 2e 90 02 06 2f 90 02 20 2f 90 02 12 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}