
rule TrojanDownloader_O97M_Emotet_VBSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.VBSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 22 26 22 31 2f 30 63 22 26 22 4a 70 22 26 22 55 4a 22 26 22 58 42 22 26 22 68 75 22 26 22 42 61 22 26 22 4d 64 22 26 22 56 57 22 26 22 51 66 2f } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Emotet_VBSM_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Emotet.VBSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {66 61 72 73 63 68 69 64 2e 64 65 2f 76 65 72 6b 61 75 66 73 62 65 72 61 74 65 72 5f 73 65 72 76 69 63 65 2f 6f 7a 72 77 33 36 61 32 79 31 63 68 32 63 6c 75 7a 79 2f } //01 00 
		$a_00_1 = {37 37 68 6f 6d 6f 6c 6f 67 2e 63 6f 6d 2e 62 72 2f 64 65 76 2d 6a 65 61 6c 76 65 73 2f 67 70 35 35 77 62 79 6e 78 6e 70 36 2f } //01 00 
		$a_00_2 = {67 65 6f 77 66 2e 67 65 2f 74 65 6d 70 6c 61 74 65 73 2f 70 6a 72 65 61 33 69 75 33 77 67 2f } //01 00 
		$a_00_3 = {68 36 33 34 30 32 78 34 2e 62 65 67 65 74 2e 74 65 63 68 2f 62 69 6e 2f 77 6c 30 65 6e 69 65 33 62 68 65 6c 78 76 36 76 2f } //00 00 
	condition:
		any of ($a_*)
 
}