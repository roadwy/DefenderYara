
rule TrojanDownloader_O97M_Emotet_PKEO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PKEO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 2f 62 75 72 67 61 72 65 6c 6c 61 71 75 61 6e 74 75 6d 68 65 61 6c 69 6e 67 2e 6f 72 67 2f 4e 52 6c 30 59 4d 42 47 4e 68 38 69 2f } //01 00 
		$a_01_1 = {2f 2f 72 6f 76 69 65 6c 2e 6d 78 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 75 58 32 57 44 46 68 72 45 2f } //01 00 
		$a_01_2 = {2f 2f 66 61 69 73 6f 6e 66 69 6c 6d 73 2e 63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 6a 6f 61 2f } //01 00 
		$a_01_3 = {2f 2f 63 6e 63 61 64 76 65 6e 74 69 73 74 2e 6f 72 67 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 39 71 69 6b 6a 56 44 38 34 42 2f } //00 00 
	condition:
		any of ($a_*)
 
}