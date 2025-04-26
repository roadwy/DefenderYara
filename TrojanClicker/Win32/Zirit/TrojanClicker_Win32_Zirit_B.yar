
rule TrojanClicker_Win32_Zirit_B{
	meta:
		description = "TrojanClicker:Win32/Zirit.B,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 0a 00 00 "
		
	strings :
		$a_00_0 = {44 6f 6d 61 69 6e 73 } //1 Domains
		$a_00_1 = {46 65 65 64 55 72 6c } //1 FeedUrl
		$a_00_2 = {54 6f 46 65 65 64 } //2 ToFeed
		$a_00_3 = {5f 73 65 6c 66 00 } //2 獟汥f
		$a_00_4 = {63 6c 69 63 6b 74 69 6d 65 } //2 clicktime
		$a_00_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 68 65 6c 6c 53 65 72 76 69 63 65 4f 62 6a 65 63 74 44 65 6c 61 79 } //4 SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelay
		$a_00_6 = {25 6c 64 2e 65 78 65 00 } //10
		$a_00_7 = {2f 25 73 3f 70 69 64 3d 25 30 34 64 26 } //10 /%s?pid=%04d&
		$a_03_8 = {57 ff d6 8b f8 ff d6 2b c7 3d 30 75 00 00 73 2b 8b 6c 24 14 8b 1d ?? ?? ?? 10 6a 00 6a 01 55 ff 15 ?? ?? ?? 10 85 c0 75 19 68 e8 03 00 00 ff d3 ff d6 2b c7 3d 30 75 00 00 72 } //20
		$a_03_9 = {83 fe ff 74 4b 8d 44 24 10 50 56 ff 15 ?? ?? ?? 10 6a 00 83 c0 da 6a 00 50 56 ff 15 ?? ?? ?? 10 8d 4c 24 0c 6a 00 51 6a 26 68 60 64 00 10 56 ff 15 } //20
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*4+(#a_00_6  & 1)*10+(#a_00_7  & 1)*10+(#a_03_8  & 1)*20+(#a_03_9  & 1)*20) >=60
 
}