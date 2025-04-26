
rule TrojanDownloader_O97M_EncDoc_ASY_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.ASY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 3a 2f 2f [0-30] 2e [0-06] 2f [0-15] 2f 78 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c } //1
		$a_03_1 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 2f 2f [0-40] 2e [0-10] 2f [0-20] 2f 62 65 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}