
rule TrojanDownloader_O97M_Adnel_K{
	meta:
		description = "TrojanDownloader:O97M/Adnel.K,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {4b 6f 47 7a 33 4f 43 6e 67 30 49 28 4e 73 55 43 62 52 20 2d 20 31 29 20 3d 20 45 4c 34 30 35 48 72 4c 42 30 76 68 28 4e 73 55 43 62 52 20 2d 20 31 29 20 58 6f 72 20 28 28 31 32 37 2e 35 20 2b 20 38 20 2b 20 31 32 37 2e 35 20 2d 20 38 29 20 2d 20 45 4c 34 30 35 48 72 4c 42 30 76 68 28 43 6c 74 6a 68 52 31 4a 69 4e 6c 6b 20 2d 20 4e 73 55 43 62 52 29 29 } //00 00 
	condition:
		any of ($a_*)
 
}