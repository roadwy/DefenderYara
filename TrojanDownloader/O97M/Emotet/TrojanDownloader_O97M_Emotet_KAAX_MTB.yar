
rule TrojanDownloader_O97M_Emotet_KAAX_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.KAAX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 62 76 69 72 74 75 61 6c 2e 63 6f 6d 2f 61 66 66 69 6e 69 74 61 2f 6b 43 4f 2f } //01 00 
		$a_01_1 = {3a 2f 2f 63 66 70 2d 63 6f 75 72 73 65 73 2e 63 6f 6d 2f 6b 65 79 2f 68 73 32 37 2f } //01 00 
		$a_01_2 = {3a 2f 2f 77 77 77 2e 66 75 6e 64 61 63 69 6f 6e 63 65 64 65 73 2e 6f 72 67 2f 5f 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 2f 6f 44 50 67 61 36 6e 66 68 6b 52 6f 2f } //01 00 
		$a_01_3 = {3a 2f 2f 62 75 69 6c 64 67 75 6a 61 72 61 74 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 6f 4a 56 37 62 6b 39 6f 6e 6d 2f } //00 00 
	condition:
		any of ($a_*)
 
}