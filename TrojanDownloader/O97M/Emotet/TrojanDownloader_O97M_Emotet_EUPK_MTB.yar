
rule TrojanDownloader_O97M_Emotet_EUPK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.EUPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 6d 65 67 61 6b 6f 6e 66 65 72 61 6e 73 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 58 7a 7a 30 38 69 35 31 34 4e 42 72 67 2f } //01 00 
		$a_01_1 = {6d 79 71 73 65 72 76 69 63 65 2e 63 6f 6d 2e 61 72 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 55 61 6d 51 6b 79 39 48 39 72 53 79 4e 37 43 57 64 75 65 2f } //01 00 
		$a_01_2 = {6e 6f 72 6f 6e 68 61 6c 61 6e 63 68 65 73 2e 63 6f 6d 2e 62 72 2f 63 67 69 2d 62 69 6e 2f 78 69 78 73 73 75 4d 4c 39 4e 4f 4a 4f 39 2f } //01 00 
		$a_01_3 = {6e 65 72 7a 2e 6e 65 74 2f 73 74 61 74 73 2f 54 58 47 52 70 4b 62 2f } //00 00 
	condition:
		any of ($a_*)
 
}