
rule TrojanDownloader_O97M_EncDoc_PKJA_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PKJA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {52 45 54 55 90 02 05 28 29 90 02 05 52 4e 90 02 0f 22 2c 22 90 02 0a 22 26 22 2f 75 22 26 22 70 6c 22 26 22 6f 61 22 26 22 64 2f 78 22 26 22 73 56 22 26 22 45 50 22 26 22 72 34 22 26 22 37 30 22 26 22 38 55 22 26 22 6b 2f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_EncDoc_PKJA_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PKJA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {52 45 54 55 90 02 20 3a 2f 90 02 40 2e 90 02 05 2f 90 02 20 2f 90 02 20 2f 22 2c 22 90 02 20 3a 2f 2f 90 02 40 2e 90 02 05 2f 90 02 20 2f 90 02 20 2f 22 2c 22 90 02 20 3a 2f 2f 90 02 40 2e 90 02 03 2f 90 02 20 2f 90 02 20 2f 22 2c 22 90 02 20 3a 2f 2f 90 02 40 2e 90 02 03 2f 90 02 20 2f 90 02 20 2f 22 2c 22 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}