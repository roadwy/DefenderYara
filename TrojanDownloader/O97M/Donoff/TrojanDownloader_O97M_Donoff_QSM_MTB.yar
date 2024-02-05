
rule TrojanDownloader_O97M_Donoff_QSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.QSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 68 65 6c 6c 28 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 63 61 6c 63 2e 63 6f 6d 20 22 22 68 74 74 70 3a 2f 2f 64 6f 63 75 6d 65 6e 74 73 2e 70 72 6f 2e 62 72 2f 69 6e 6a 63 74 69 6f 6e 2e 6d 70 33 } //00 00 
	condition:
		any of ($a_*)
 
}