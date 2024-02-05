
rule TrojanDownloader_O97M_Emotet_BOAF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.BOAF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 62 6f 73 6e 79 2e 63 6f 6d 2f 61 73 70 6e 65 74 5f 63 6c 69 65 6e 74 2f 4e 47 54 78 31 46 55 7a 71 2f } //01 00 
		$a_01_1 = {3a 2f 2f 77 77 77 2e 62 65 72 65 6b 65 74 68 61 62 65 72 2e 63 6f 6d 2f 68 61 74 61 78 2f 63 37 63 72 47 64 65 6a 57 34 33 38 30 4f 52 75 78 71 52 2f } //01 00 
		$a_01_2 = {3a 2f 2f 62 75 6c 6c 64 6f 67 69 72 6f 6e 77 6f 72 6b 73 6c 6c 63 2e 63 6f 6d 2f 74 65 6d 70 2f 42 42 68 35 48 48 70 65 69 2f } //00 00 
	condition:
		any of ($a_*)
 
}