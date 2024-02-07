
rule TrojanDownloader_O97M_Donoff_AO{
	meta:
		description = "TrojanDownloader:O97M/Donoff.AO,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 44 65 63 6f 64 65 42 61 73 65 36 34 28 22 56 45 56 4e 55 41 3d 3d 22 29 } //01 00  = DecodeBase64("VEVNUA==")
		$a_01_1 = {28 22 58 47 56 34 59 32 56 73 63 47 78 31 5a 32 6c 75 4c 6d 56 34 5a 51 3d 3d 22 29 } //01 00  ("XGV4Y2VscGx1Z2luLmV4ZQ==")
		$a_01_2 = {54 56 4e 59 54 55 77 79 4c 6c 68 4e 54 45 68 55 56 46 41 3d } //01 00  TVNYTUwyLlhNTEhUVFA=
		$a_01_3 = {28 22 52 30 56 55 22 29 } //01 00  ("R0VU")
		$a_01_4 = {74 68 65 66 69 6c 65 20 3d 20 45 6e 76 69 72 6f 6e 28 74 65 6d 70 65 29 20 26 20 66 69 6c 65 65 } //01 00  thefile = Environ(tempe) & filee
		$a_01_5 = {53 68 65 6c 6c 20 74 68 65 66 69 6c 65 2c 20 76 62 4d 61 78 69 6d 69 7a 65 64 46 6f 63 75 73 } //01 00  Shell thefile, vbMaximizedFocus
		$a_01_6 = {61 48 52 30 63 44 6f 76 4c 33 64 33 64 79 35 68 5a 47 39 69 5a 57 46 70 63 69 35 75 5a 58 51 76 4d 53 35 6b 59 58 51 3d } //00 00  aHR0cDovL3d3dy5hZG9iZWFpci5uZXQvMS5kYXQ=
		$a_00_7 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}