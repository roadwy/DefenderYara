
rule TrojanDownloader_O97M_Donoff_BN{
	meta:
		description = "TrojanDownloader:O97M/Donoff.BN,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {22 4e 65 77 4d 61 63 72 6f 73 22 0d 0a 53 75 62 } //01 00  丢睥慍牣獯ഢ匊扵
		$a_00_1 = {23 49 66 20 57 69 6e 36 34 20 54 68 65 6e 0d 0a 50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_BN_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.BN,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 58 73 73 44 62 67 77 7a 4f 32 32 65 62 62 20 3d 20 53 6d 48 45 35 38 47 45 71 39 49 20 2d 20 28 28 53 6d 48 45 35 38 47 45 71 39 49 20 5c 20 61 63 50 77 67 31 29 20 2a 20 61 63 50 77 67 31 29 } //01 00  SXssDbgwzO22ebb = SmHE58GEq9I - ((SmHE58GEq9I \ acPwg1) * acPwg1)
		$a_00_1 = {6a 66 39 55 58 4c 64 4e 47 54 47 65 59 78 7a 20 3d 20 28 4b 7a 4e 71 45 38 74 36 54 50 32 42 76 36 33 20 2d 20 45 33 49 66 77 6d 68 68 75 79 6b 29 20 2f 20 72 43 67 4e 4b 55 49 4a 54 4c 57 } //01 00  jf9UXLdNGTGeYxz = (KzNqE8t6TP2Bv63 - E3Ifwmhhuyk) / rCgNKUIJTLW
		$a_00_2 = {59 41 61 38 35 75 38 28 59 6e 4a 68 6b 33 46 37 64 72 66 4c 76 2c 20 28 4a 57 63 62 66 51 6c 64 39 69 30 20 2a 20 45 33 49 66 77 6d 68 68 75 79 6b 29 20 2b 20 71 51 63 38 6a 35 69 52 6c 6e 63 63 29 29 } //00 00  YAa85u8(YnJhk3F7drfLv, (JWcbfQld9i0 * E3Ifwmhhuyk) + qQc8j5iRlncc))
	condition:
		any of ($a_*)
 
}