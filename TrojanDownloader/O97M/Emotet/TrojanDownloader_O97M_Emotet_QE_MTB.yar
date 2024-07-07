
rule TrojanDownloader_O97M_Emotet_QE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.QE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6d 67 6d 74 90 02 15 69 90 02 15 3a 90 02 15 57 90 02 15 69 90 02 15 6e 90 02 15 33 90 02 15 32 90 02 15 50 90 02 15 72 90 02 15 6f 90 02 15 63 90 02 15 65 90 02 15 73 90 02 15 73 90 02 15 22 29 90 00 } //1
		$a_03_1 = {2e 43 72 65 61 74 65 28 90 02 25 20 2b 20 90 02 25 2c 20 90 02 25 2c 20 90 02 25 2c 20 90 02 25 29 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}