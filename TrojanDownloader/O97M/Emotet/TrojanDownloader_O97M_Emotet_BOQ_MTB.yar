
rule TrojanDownloader_O97M_Emotet_BOQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.BOQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {65 28 22 63 90 02 15 3a 90 02 15 5c 70 90 02 15 72 6f 90 02 15 67 72 90 02 15 61 6d 90 02 15 64 90 02 15 61 74 90 02 15 61 5c 90 02 20 2e 62 61 74 22 2c 22 90 02 15 22 2c 22 22 29 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}