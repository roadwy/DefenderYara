
rule TrojanDownloader_O97M_Emotet_AMTA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.AMTA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {22 68 22 26 22 74 74 22 26 22 70 [0-9f] 22 2c 22 [0-ff] 22 68 22 26 22 74 74 22 26 22 70 } //1
		$a_03_1 = {22 68 22 26 22 74 74 22 26 22 70 [0-9f] 22 2c 22 [0-ff] 22 68 22 26 22 74 74 70 22 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}