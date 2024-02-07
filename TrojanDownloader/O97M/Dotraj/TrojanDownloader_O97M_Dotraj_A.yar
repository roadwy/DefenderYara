
rule TrojanDownloader_O97M_Dotraj_A{
	meta:
		description = "TrojanDownloader:O97M/Dotraj.A,SIGNATURE_TYPE_MACROHSTR_EXT,11 00 11 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {20 3d 20 43 68 72 28 90 1f 03 00 29 20 2b 20 43 68 72 28 90 1f 03 00 29 20 2b 20 43 68 72 28 90 1f 03 00 29 20 2b 20 43 68 72 28 90 1f 03 00 29 20 2b 20 43 68 72 28 90 00 } //01 00 
		$a_00_1 = {43 61 6c 6c 20 53 68 65 6c 6c 28 } //05 00  Call Shell(
		$a_00_2 = {4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 47 65 74 54 68 72 65 61 64 49 6e 66 6f 72 6d 61 74 69 6f 6e } //05 00  Lib "kernel32" Alias "GetThreadInformation
		$a_00_3 = {4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 43 68 65 63 6b 45 6c 65 76 61 74 69 6f 6e } //05 00  Lib "kernel32" Alias "CheckElevation
		$a_00_4 = {4c 69 62 20 22 75 72 6c 6d 6f 6e 22 20 41 6c 69 61 73 20 22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00  Lib "urlmon" Alias "URLDownloadToFileA
		$a_00_5 = {5d 04 00 00 2b c7 03 80 5c 34 } //00 00 
	condition:
		any of ($a_*)
 
}