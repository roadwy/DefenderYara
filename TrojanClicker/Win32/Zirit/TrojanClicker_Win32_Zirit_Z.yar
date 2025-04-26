
rule TrojanClicker_Win32_Zirit_Z{
	meta:
		description = "TrojanClicker:Win32/Zirit.Z,SIGNATURE_TYPE_PEHSTR_EXT,46 00 43 00 0d 00 00 "
		
	strings :
		$a_00_0 = {64 6f 6d 61 69 6e 73 } //3 domains
		$a_01_1 = {46 65 65 64 55 72 6c } //3 FeedUrl
		$a_01_2 = {54 6f 46 65 65 64 } //3 ToFeed
		$a_01_3 = {5f 73 65 6c 66 00 } //3 獟汥f
		$a_01_4 = {4f 62 6a 65 63 74 44 65 6c 61 79 } //3 ObjectDelay
		$a_01_5 = {3f 70 69 64 3d 25 30 34 64 26 } //3 ?pid=%04d&
		$a_01_6 = {43 4c 53 49 44 5c 25 73 5c 49 } //3 CLSID\%s\I
		$a_01_7 = {52 65 73 6f 75 72 63 65 73 2e 64 6c 6c } //3 Resources.dll
		$a_01_8 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //3 URLDownloadToFileA
		$a_01_9 = {73 65 74 75 70 2e 6d 73 70 75 62 6c 69 6b 2e 63 6f 6d } //3 setup.mspublik.com
		$a_01_10 = {73 65 74 75 70 2e 6a 6f 62 75 73 69 6e 65 73 73 2e 6f 72 67 } //3 setup.jobusiness.org
		$a_03_11 = {2b c7 3d 30 75 00 00 73 2b 8b 6c 24 14 8b 1d ?? ?? 00 10 6a 00 6a 01 55 ff 15 ?? ?? 00 10 85 c0 75 ?? 68 e8 03 00 00 ff d3 ff d6 2b c7 3d 30 75 00 00 72 } //20
		$a_03_12 = {8b f0 83 fe ff 74 [0-18] 83 c0 da } //20
	condition:
		((#a_00_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3+(#a_01_6  & 1)*3+(#a_01_7  & 1)*3+(#a_01_8  & 1)*3+(#a_01_9  & 1)*3+(#a_01_10  & 1)*3+(#a_03_11  & 1)*20+(#a_03_12  & 1)*20) >=67
 
}