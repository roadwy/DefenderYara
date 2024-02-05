
rule TrojanDownloader_O97M_Emotet_BOEW_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.BOEW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 6c 69 74 74 6c 65 73 77 65 65 74 2e 63 6f 2e 75 6b 2f 77 70 2d 61 20 64 6d 69 6e 2f 76 6b 6f 2f } //01 00 
		$a_01_1 = {3a 2f 2f 73 74 72 61 74 75 73 65 62 73 6f 6c 75 74 69 6f 6e 73 2e 63 6f 2e 6e 7a 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 77 79 45 20 45 6a 35 6a 48 38 78 71 35 30 72 70 31 2f } //01 00 
		$a_01_2 = {3a 2f 2f 77 76 66 73 62 72 61 73 69 6c 2e 63 6f 6d 2e 62 72 2f 41 63 72 61 73 69 65 61 65 2f 4c 49 59 4e 4f 71 43 74 68 66 5a 75 43 57 51 7a 33 2f } //01 00 
		$a_01_3 = {3a 2f 2f 6c 79 64 74 2e 63 63 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 36 73 66 59 6f 2f } //01 00 
		$a_01_4 = {3a 2f 2f 6c 70 6d 2e 66 6b 2e 75 62 2e 61 63 2e 69 64 20 2f 46 6f 78 2d 43 2f 66 61 4b 77 53 36 70 36 2f } //00 00 
	condition:
		any of ($a_*)
 
}