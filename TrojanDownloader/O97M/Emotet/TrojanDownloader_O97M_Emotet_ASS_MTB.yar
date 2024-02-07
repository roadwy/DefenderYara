
rule TrojanDownloader_O97M_Emotet_ASS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.ASS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 69 73 67 75 76 65 6e 6c 69 67 69 62 75 72 61 64 61 2e 63 6f 6d 2f 78 63 67 2f 75 5a 53 55 2f } //00 00  https://isguvenligiburada.com/xcg/uZSU/
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Emotet_ASS_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Emotet.ASS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 73 75 6c 65 79 65 72 61 2e 63 6f 6d 2f 63 6f 6d 70 6f 6e 65 6e 74 73 2f 90 02 2f 2f 90 00 } //01 00 
		$a_03_1 = {68 74 74 70 3a 2f 2f 73 6f 63 69 61 6c 6c 79 73 61 76 76 79 73 65 6f 2e 63 6f 6d 2f 50 69 6e 6e 61 63 6c 65 44 79 6e 61 6d 69 63 53 65 72 76 69 63 65 73 2f 90 02 2f 2f 90 00 } //01 00 
		$a_03_2 = {68 74 74 70 3a 2f 2f 73 68 61 62 65 65 72 70 76 2e 61 74 77 65 62 70 61 67 65 73 2e 63 6f 6d 2f 63 73 73 2f 90 02 2f 2f 90 00 } //01 00 
		$a_03_3 = {68 74 74 70 73 3a 2f 2f 73 63 68 77 69 7a 65 72 2e 6e 65 74 2f 73 74 79 6c 65 64 2f 90 02 2f 2f 90 00 } //01 00 
		$a_03_4 = {68 74 74 70 3a 2f 2f 73 68 69 6d 61 6c 2e 61 74 77 65 62 70 61 67 65 73 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 90 02 2f 2f 90 00 } //01 00 
		$a_03_5 = {68 74 74 70 3a 2f 2f 6d 6f 76 65 69 74 2e 73 61 76 76 79 69 6e 74 2e 63 6f 6d 2f 63 6f 6e 66 69 67 2f 90 02 2f 2f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}