
rule TrojanDownloader_Win32_Zlob_KA{
	meta:
		description = "TrojanDownloader:Win32/Zlob.KA,SIGNATURE_TYPE_PEHSTR_EXT,4a 00 48 00 09 00 00 "
		
	strings :
		$a_00_0 = {79 61 68 6f 6f 2e } //10 yahoo.
		$a_00_1 = {67 6f 6f 67 6c 65 2e } //10 google.
		$a_00_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 53 65 61 72 63 68 53 63 6f 70 65 73 } //10 Software\Microsoft\Internet Explorer\SearchScopes
		$a_00_3 = {44 65 66 61 75 6c 74 53 63 6f 70 65 } //10 DefaultScope
		$a_00_4 = {47 65 74 53 79 73 74 65 6d 44 65 66 61 75 6c 74 4c 43 49 44 } //10 GetSystemDefaultLCID
		$a_00_5 = {48 74 74 70 4f 70 65 6e 52 65 71 75 65 73 74 41 } //10 HttpOpenRequestA
		$a_00_6 = {5f 52 45 44 44 5f } //2 _REDD_
		$a_00_7 = {47 65 74 55 73 65 72 44 65 66 61 75 6c 74 4c 43 49 44 } //2 GetUserDefaultLCID
		$a_02_8 = {56 8b 74 24 08 8a 16 84 d2 b8 90 01 04 8b c8 74 10 2b f0 32 54 24 0c 88 11 41 8a 14 0e 84 d2 75 f2 c6 01 00 5e 90 00 } //10
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*10+(#a_00_6  & 1)*2+(#a_00_7  & 1)*2+(#a_02_8  & 1)*10) >=72
 
}