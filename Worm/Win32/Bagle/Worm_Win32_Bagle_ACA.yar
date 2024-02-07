
rule Worm_Win32_Bagle_ACA{
	meta:
		description = "Worm:Win32/Bagle.ACA,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {46 69 6e 64 46 69 72 73 74 55 72 6c 43 61 63 68 65 45 6e 74 72 79 41 } //01 00  FindFirstUrlCacheEntryA
		$a_01_1 = {47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 53 74 72 69 6e 67 73 41 } //01 00  GetLogicalDriveStringsA
		$a_01_2 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //03 00  CreateToolhelp32Snapshot
		$a_01_3 = {c9 c3 5c 00 2a 2e 2a 00 53 59 53 54 45 4d 5c 43 } //03 00 
		$a_01_4 = {20 4d 61 6e 61 67 65 72 00 21 5c 3f 3f 5c 43 3a } //03 00  䴠湡条牥℀㽜尿㩃
		$a_01_5 = {74 69 6f 6e 73 00 55 8b ec 81 c4 } //00 00 
	condition:
		any of ($a_*)
 
}