
rule TrojanDownloader_O97M_EncDoc_HYSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.HYSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 2f 35 34 2e 32 34 39 2e 32 31 30 2e 34 34 2f 78 69 2f 6c 6f 61 64 65 72 2f 75 70 6c 6f 61 64 73 2f 4d 54 2d 30 37 36 31 30 31 33 35 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}