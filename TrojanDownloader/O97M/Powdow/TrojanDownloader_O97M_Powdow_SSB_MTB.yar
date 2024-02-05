
rule TrojanDownloader_O97M_Powdow_SSB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SSB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {5e 70 2a 6f 5e 2a 77 2a 65 2a 72 2a 73 5e 5e 2a 68 2a 65 2a 6c 5e 2a 6c 2a 20 2a 5e 2d 2a 57 2a 69 2a 6e 2a 5e 64 2a 6f 2a 77 5e 2a 53 2a 74 2a 79 2a 5e 6c 2a 65 2a 20 2a 68 2a 69 2a 5e 64 2a 64 2a 5e 65 2a 6e 5e 2a 20 2a 2d 2a 65 2a 78 2a 5e 65 2a 63 2a 75 2a 74 2a 5e 69 2a 6f 2a 6e 2a 70 6f 6c 5e 69 63 79 2a 20 2a 62 2a 79 70 5e 5e 61 73 73 2a 3b } //01 00 
		$a_01_1 = {49 6e 5e 76 6f 2a 6b 65 2d 57 65 5e 62 52 65 2a 71 75 65 73 74 20 2d 55 5e 72 69 20 22 22 68 74 74 70 3a 2f 2f 36 32 2e 32 33 33 2e 35 37 2e 31 39 30 2f 7a 31 2f 71 75 6f 74 65 31 31 31 2e 65 78 65 22 22 20 2d 4f 75 74 2a 46 69 6c 65 20 24 54 65 6d 70 46 69 6c 65 3b 20 53 74 2a 61 72 74 2d 50 72 6f 63 65 2a 73 73 20 24 54 65 6d 70 46 69 6c 65 3b } //00 00 
	condition:
		any of ($a_*)
 
}