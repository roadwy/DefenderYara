
rule TrojanClicker_Win32_Zirit_C{
	meta:
		description = "TrojanClicker:Win32/Zirit.C,SIGNATURE_TYPE_PEHSTR_EXT,ffffffd1 00 ffffffd1 00 08 00 00 "
		
	strings :
		$a_00_0 = {44 6f 6d 61 69 6e 73 } //1 Domains
		$a_00_1 = {46 65 65 64 55 72 6c } //1 FeedUrl
		$a_00_2 = {54 6f 46 65 65 64 } //1 ToFeed
		$a_00_3 = {63 6c 69 63 6b 73 } //1 clicks
		$a_00_4 = {63 6c 69 63 6b 74 69 6d 65 } //1 clicktime
		$a_00_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 68 65 6c 6c 53 65 72 76 69 63 65 4f 62 6a 65 63 74 44 65 6c 61 79 } //4 SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelay
		$a_02_6 = {50 6a 00 6a 00 68 90 01 03 10 6a 00 6a 00 ff d7 8b 1d 90 01 03 10 be 0a 00 00 00 8d 4c 24 0c 51 6a 00 6a 00 68 90 01 03 10 6a 00 6a 00 ff d7 68 90 01 04 ff d3 90 00 } //100
		$a_02_7 = {53 83 c0 da 53 50 56 ff 15 90 01 03 10 8d 90 01 03 53 51 6a 26 68 90 01 03 10 56 ff 15 90 01 03 10 90 00 } //100
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*4+(#a_02_6  & 1)*100+(#a_02_7  & 1)*100) >=209
 
}