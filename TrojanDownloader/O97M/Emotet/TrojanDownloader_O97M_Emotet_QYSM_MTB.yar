
rule TrojanDownloader_O97M_Emotet_QYSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.QYSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 61 6e 61 6d 65 6c 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 46 42 50 48 53 48 4e 31 41 64 56 70 6e 2f } //01 00 
		$a_01_1 = {70 61 70 69 6c 6c 6f 6e 77 65 62 2e 66 72 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 51 54 64 66 2f } //01 00 
		$a_01_2 = {77 77 77 2e 70 69 6f 6e 65 65 72 69 6d 6d 69 67 72 61 74 69 6f 6e 2e 63 6f 2e 69 6e 2f 69 63 6f 6e 2f 5a 35 7a 35 56 78 2f } //01 00 
		$a_01_3 = {61 70 70 2e 76 69 72 61 70 61 64 2e 69 72 2f 61 73 73 65 74 73 2f 30 36 4c 44 39 34 33 72 2f } //00 00 
	condition:
		any of ($a_*)
 
}