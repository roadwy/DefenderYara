
rule TrojanDownloader_O97M_Emotet_CCPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.CCPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 78 67 65 76 31 2e 6f 63 78 } //01 00  \xgev1.ocx
		$a_01_1 = {5c 78 67 65 76 32 2e 6f 63 78 } //01 00  \xgev2.ocx
		$a_01_2 = {5c 78 67 65 76 33 2e 6f 63 78 } //01 00  \xgev3.ocx
		$a_03_3 = {75 72 6c 6d 6f 6e 90 02 03 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}