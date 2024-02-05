
rule TrojanDownloader_O97M_Emotet_ESPK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.ESPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 69 63 72 6f 6c 65 6e 74 2e 63 6f 6d 2f 61 64 6d 69 6e 2f 33 2f } //01 00 
		$a_01_1 = {6d 63 61 70 75 62 6c 69 63 73 63 68 6f 6f 6c 2e 63 6f 6d 2f 41 63 68 69 65 76 65 6d 65 6e 74 73 2f 72 34 70 73 76 2f } //01 00 
		$a_01_2 = {6b 75 6c 75 63 6b 61 63 69 2e 63 6f 6d 2f 79 61 72 69 73 6d 61 2f 63 67 69 2d 62 69 6e 2f 61 49 75 49 34 55 6b 64 74 6c 37 33 30 73 50 31 46 2f } //01 00 
		$a_01_3 = {6d 6f 6f 72 77 6f 72 6c 64 2e 63 6f 6d 2f 61 73 70 6e 65 74 5f 63 6c 69 65 6e 74 2f 66 54 44 4a 4f 64 54 61 31 55 53 4b 6c 34 33 77 46 74 6e 62 2f } //00 00 
	condition:
		any of ($a_*)
 
}