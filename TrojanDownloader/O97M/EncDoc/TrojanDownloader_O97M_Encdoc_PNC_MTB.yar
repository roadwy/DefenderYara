
rule TrojanDownloader_O97M_Encdoc_PNC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Encdoc.PNC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6d 44 2e 65 58 45 20 20 2f 63 20 70 6f 77 45 72 53 48 45 6c 4c 20 20 2d 65 78 20 62 79 70 61 53 73 20 2d 6e 6f 70 20 2d 77 20 31 } //01 00 
		$a_00_1 = {69 45 58 28 20 63 55 72 6c 20 20 28 27 68 74 74 70 73 3a 2f 2f 74 65 78 6e 74 72 61 64 65 2e 63 6f 2e 75 6b 2f 6c 69 6e 6b 2f 65 78 27 20 20 2b 20 27 63 65 6c 2e 6a 27 20 20 2b 20 27 70 27 20 20 2b 20 27 67 27 20 29 29 } //00 00 
	condition:
		any of ($a_*)
 
}