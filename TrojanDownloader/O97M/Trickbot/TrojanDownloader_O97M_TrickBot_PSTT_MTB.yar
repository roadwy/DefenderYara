
rule TrojanDownloader_O97M_TrickBot_PSTT_MTB{
	meta:
		description = "TrojanDownloader:O97M/TrickBot.PSTT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {46 75 6e 63 74 69 6f 6e 20 61 72 72 61 79 4f 62 6a 65 63 74 42 75 74 74 28 29 90 0c 02 00 61 72 72 61 79 4f 62 6a 65 63 74 42 75 74 74 20 3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 22 20 26 20 77 69 6e 64 6f 77 4c 73 74 29 90 00 } //01 00 
		$a_03_1 = {46 75 6e 63 74 69 6f 6e 20 77 69 6e 64 6f 77 4c 73 74 28 29 90 0c 02 00 77 69 6e 64 6f 77 4c 73 74 20 3d 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 62 6f 78 44 65 6c 49 6e 64 2e 68 74 61 22 90 0c 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}