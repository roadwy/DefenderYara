
rule TrojanDownloader_O97M_EncDoc_QZSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.QZSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {27 29 27 27 73 62 76 2e 64 61 70 65 74 6f 6e 5c 27 27 2b 70 6d 65 74 3a 76 6e 65 24 2c 27 27 73 62 76 2e 74 6e 65 69 6c 43 20 64 65 74 63 65 74 6f 72 50 2f [0-10] 2f [0-10] 2f 2f 3a 70 74 74 68 27 27 28 65 6c 69 46 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}