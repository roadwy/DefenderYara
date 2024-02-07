
rule TrojanDownloader_O97M_Donoff_U{
	meta:
		description = "TrojanDownloader:O97M/Donoff.U,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {3d 20 4c 65 66 74 28 53 74 72 43 6f 6e 76 28 } //01 00  = Left(StrConv(
		$a_00_1 = {2c 20 76 62 55 6e 69 63 6f 64 65 29 2c 20 55 42 6f 75 6e 64 28 } //01 00  , vbUnicode), UBound(
		$a_00_2 = {48 43 41 4b 53 42 43 32 50 49 55 56 43 42 32 50 49 33 47 49 4c 55 48 47 43 49 55 47 55 59 4f 32 46 33 55 43 32 55 59 33 46 4f 32 33 4f 55 59 43 46 33 32 4f 59 55 44 48 4f 59 47 55 33 32 46 56 59 55 4f 32 33 47 46 } //00 00  HCAKSBC2PIUVCB2PI3GILUHGCIUGUYO2F3UC2UY3FO23OUYCF32OYUDHOYGU32FVYUO23GF
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_U_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.U,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 44 44 20 3d 20 22 68 74 74 70 73 3a 2f 2f } //01 00  GDD = "https://
		$a_01_1 = {68 65 6c 6c 6f 5f 77 6f 72 6c 64 2e 65 78 65 22 } //01 00  hello_world.exe"
		$a_01_2 = {66 75 63 6b 61 76 } //01 00  fuckav
		$a_02_3 = {3d 20 45 6e 76 69 72 6f 6e 28 22 41 50 50 44 41 54 41 22 29 0d 0a 90 05 10 06 61 2d 7a 30 2d 39 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 90 05 10 06 61 2d 7a 30 2d 39 2c 20 46 61 6c 73 65 0d 0a 90 05 10 06 61 2d 7a 30 2d 39 2e 53 65 6e 64 90 00 } //01 00 
		$a_02_4 = {2e 77 72 69 74 65 20 90 05 10 06 61 2d 7a 30 2d 39 2e 72 65 73 70 6f 6e 73 65 42 6f 64 79 0d 0a 2e 53 61 76 65 54 6f 46 69 6c 65 20 90 05 10 06 61 2d 7a 30 2d 39 20 26 20 22 5c 90 02 20 22 2c 20 32 0d 0a 45 6e 64 20 57 69 74 68 0d 0a 53 68 65 6c 6c 20 90 05 10 06 61 2d 7a 30 2d 39 20 26 20 22 5c 90 00 } //00 00 
		$a_00_5 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}