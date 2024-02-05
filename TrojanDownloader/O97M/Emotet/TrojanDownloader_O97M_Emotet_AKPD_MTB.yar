
rule TrojanDownloader_O97M_Emotet_AKPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.AKPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 77 65 62 6f 63 75 6c 74 61 2e 63 6f 6d 2f 41 50 50 73 2f 6a 62 37 75 72 4c 54 32 73 2f } //01 00 
		$a_01_1 = {3a 2f 2f 77 65 62 67 75 72 75 69 6e 64 69 61 2e 63 6f 6d 2f 74 68 65 6d 65 2f 41 37 49 64 73 45 6b 31 75 4a 6f 2f } //01 00 
		$a_01_2 = {3a 2f 2f 77 61 76 65 73 2d 69 6e 64 69 61 2e 63 6f 6d 2f 4c 43 2f 59 6f 6c 71 54 43 47 50 63 42 58 30 68 2f } //00 00 
	condition:
		any of ($a_*)
 
}