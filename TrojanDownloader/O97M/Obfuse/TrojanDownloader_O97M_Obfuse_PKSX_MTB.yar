
rule TrojanDownloader_O97M_Obfuse_PKSX_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PKSX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {63 6f 6d 2f 66 69 6c 65 2f 70 33 61 79 34 69 74 30 38 6a 31 73 37 68 70 2f 30 6d 61 69 6e 2e 68 74 6d 2f 66 69 6c 65 90 0a 60 00 68 74 74 70 73 3a 2f 2f 74 61 78 66 69 6c 65 2e 6d 65 64 69 61 66 69 72 65 2e 90 00 } //01 00 
		$a_01_1 = {27 2c 27 77 69 6e 6d 67 6d 74 73 3a 27 2c 27 } //01 00  ','winmgmts:','
		$a_01_2 = {43 3a 5c 78 35 63 50 72 6f 67 72 61 6d 44 61 74 61 5c 78 35 63 64 64 6f 6e 64 2e 63 6f 6d } //01 00  C:\x5cProgramData\x5cddond.com
		$a_01_3 = {3d 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 75 70 64 61 74 65 2e 6a 73 22 } //01 00  = "C:\Users\Public\update.js"
		$a_01_4 = {27 2c 27 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 53 74 61 72 74 75 70 27 2c 27 } //00 00  ','Win32_ProcessStartup','
	condition:
		any of ($a_*)
 
}