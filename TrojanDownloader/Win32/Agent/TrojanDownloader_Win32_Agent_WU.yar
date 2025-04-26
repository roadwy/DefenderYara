
rule TrojanDownloader_Win32_Agent_WU{
	meta:
		description = "TrojanDownloader:Win32/Agent.WU,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 09 00 0c 00 00 "
		
	strings :
		$a_01_0 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //1 InternetReadFile
		$a_01_1 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
		$a_01_2 = {49 6e 74 65 72 6e 65 74 43 6c 6f 73 65 48 61 6e 64 6c 65 } //1 InternetCloseHandle
		$a_01_3 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //1 InternetOpenA
		$a_00_4 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 29 } //1 Mozilla/4.0 (compatible)
		$a_00_5 = {25 73 5c 25 73 } //1 %s\%s
		$a_00_6 = {68 74 74 70 3a 2f 2f 6d 61 78 2d 73 74 61 74 73 2e 63 6f 6d } //2 http://max-stats.com
		$a_00_7 = {68 74 74 70 3a 2f 2f 73 63 2d 63 61 73 68 2e 63 6f 6d } //2 http://sc-cash.com
		$a_00_8 = {77 77 77 2e 74 65 65 6e 34 2d 73 65 78 2e 63 6f 6d } //1 www.teen4-sex.com
		$a_00_9 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 70 72 65 66 } //2 C:\WINDOWS\SYSTEM32\pref
		$a_00_10 = {63 32 2e 70 68 70 3f 69 3d } //2 c2.php?i=
		$a_00_11 = {77 69 6e 6c 6f 67 6f 6e 33 32 2e } //1 winlogon32.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*2+(#a_00_7  & 1)*2+(#a_00_8  & 1)*1+(#a_00_9  & 1)*2+(#a_00_10  & 1)*2+(#a_00_11  & 1)*1) >=9
 
}