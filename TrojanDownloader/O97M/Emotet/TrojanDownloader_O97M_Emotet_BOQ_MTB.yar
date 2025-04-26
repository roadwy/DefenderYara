
rule TrojanDownloader_O97M_Emotet_BOQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.BOQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {65 28 22 63 [0-15] 3a [0-15] 5c 70 [0-15] 72 6f [0-15] 67 72 [0-15] 61 6d [0-15] 64 [0-15] 61 74 [0-15] 61 5c [0-20] 2e 62 61 74 22 2c 22 [0-15] 22 2c 22 22 29 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}