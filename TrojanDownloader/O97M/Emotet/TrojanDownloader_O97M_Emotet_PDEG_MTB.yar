
rule TrojanDownloader_O97M_Emotet_PDEG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PDEG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 73 75 62 62 61 6c 61 6b 73 68 6d 69 2e 63 6f 6d 2f 64 61 74 61 5f 77 69 6e 6e 69 6e 67 2f 6b 59 76 36 78 62 2f } //01 00 
		$a_01_1 = {3a 2f 2f 77 65 62 68 6f 61 6e 67 67 69 61 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 72 36 66 33 76 76 38 75 6b 69 5a 6a 65 57 2f } //01 00 
		$a_01_2 = {3a 2f 2f 77 77 77 2e 63 6f 6e 74 72 6f 6c 6e 65 74 77 6f 72 6b 73 2e 63 6f 6d 2e 61 75 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 50 67 62 34 33 69 6b 54 49 6f 62 48 2f } //00 00 
	condition:
		any of ($a_*)
 
}