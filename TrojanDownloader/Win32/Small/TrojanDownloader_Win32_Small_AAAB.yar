
rule TrojanDownloader_Win32_Small_AAAB{
	meta:
		description = "TrojanDownloader:Win32/Small.AAAB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 0f 00 07 00 00 0a 00 "
		
	strings :
		$a_00_0 = {42 35 41 43 34 39 41 32 2d 39 34 46 33 2d 34 32 42 44 2d 46 34 33 34 2d 32 36 30 34 38 31 32 43 38 39 37 44 } //02 00  B5AC49A2-94F3-42BD-F434-2604812C897D
		$a_00_1 = {62 65 6e 73 6f 72 74 79 2e 64 6c 6c } //01 00  bensorty.dll
		$a_02_2 = {68 74 74 70 3a 2f 2f 67 69 63 69 61 2e 69 6e 66 6f 2f 63 64 2f 63 64 2e 70 68 70 3f 69 64 3d 25 73 26 76 65 72 3d 67 90 01 01 31 90 00 } //01 00 
		$a_02_3 = {68 74 74 70 3a 2f 2f 6d 61 73 67 69 4f 2e 69 6e 66 6f 2f 63 64 2f 63 64 2e 70 68 70 3f 69 64 3d 25 73 26 76 65 72 3d 67 90 01 01 31 90 00 } //01 00 
		$a_02_4 = {68 74 74 70 3a 2f 2f 66 31 76 69 73 61 2e 69 6e 66 6f 2f 63 64 2f 63 64 2e 70 68 70 3f 69 64 3d 25 73 26 76 65 72 3d 67 90 01 01 31 90 00 } //01 00 
		$a_00_5 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //01 00  OpenProcess
		$a_00_6 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00  URLDownloadToFileA
	condition:
		any of ($a_*)
 
}