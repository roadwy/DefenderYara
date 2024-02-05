
rule TrojanDownloader_O97M_IcedID_RESM_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.RESM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 6e 26 6c 64 33 6c 75 26 32 } //01 00 
		$a_03_1 = {72 61 72 74 64 3a 5c 70 5c 63 61 61 6f 67 6d 22 29 26 90 02 1f 28 31 32 29 26 90 02 1f 28 22 64 6c 2e 6c 90 00 } //01 00 
		$a_01_2 = {63 2f 68 75 72 6c 66 3a 31 75 6f 70 63 31 79 74 72 6c 6e 72 63 76 } //00 00 
	condition:
		any of ($a_*)
 
}