
rule TrojanDownloader_O97M_Powdow_PDAA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PDAA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 4f 57 45 52 73 68 45 6c 6c 2e 45 78 45 20 77 47 65 74 20 68 74 74 70 73 3a 2f 2f 77 77 77 37 32 2e 7a 69 70 70 79 73 68 61 72 65 2e 63 6f 6d 2f 64 2f 43 44 45 37 71 58 57 5a 2f 32 37 31 38 32 2f 46 75 64 2e 65 78 65 } //01 00 
		$a_01_1 = {2d 6f 75 74 46 49 6c 45 20 6f 2e 65 78 65 20 20 20 3b 20 2e 5c 6f 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}