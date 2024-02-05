
rule TrojanDownloader_O97M_Emotet_PDG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PDG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 63 61 72 72 65 74 69 6c 68 61 2e 6e 65 74 2f 77 68 61 74 73 2f 52 53 4c 35 30 42 6c 52 50 30 61 36 68 6a 2f } //01 00 
		$a_01_1 = {3a 2f 2f 73 68 72 69 6e 61 6e 64 72 61 6a 6f 76 65 72 73 65 61 73 2e 63 6f 6d 2f 6f 6c 64 2f 77 51 58 74 79 30 77 6e 56 44 59 2f } //01 00 
		$a_01_2 = {3a 2f 2f 7a 69 6f 6e 69 6d 6f 76 65 69 73 2e 63 6f 6d 2e 62 72 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 42 6e 30 30 67 61 77 2f } //01 00 
		$a_01_3 = {3a 2f 2f 6b 6f 6e 74 61 63 73 67 6f 2e 70 6c 2f 6d 2f 75 77 5a 59 4e 55 6a 47 65 57 57 2f } //01 00 
		$a_01_4 = {3a 2f 2f 76 70 73 33 36 31 35 33 2e 70 75 62 6c 69 63 63 6c 6f 75 64 2e 63 6f 6d 2e 62 72 2f 77 70 2d 61 64 6d 69 6e 2f 52 66 41 5a 5a 37 37 36 75 4d 4e 68 53 70 4f 54 2f } //00 00 
	condition:
		any of ($a_*)
 
}