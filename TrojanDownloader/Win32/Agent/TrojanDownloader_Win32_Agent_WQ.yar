
rule TrojanDownloader_Win32_Agent_WQ{
	meta:
		description = "TrojanDownloader:Win32/Agent.WQ,SIGNATURE_TYPE_PEHSTR,0b 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //1 Software\Microsoft\Windows NT\CurrentVersion\Winlogon
		$a_01_1 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 explorer.exe
		$a_01_2 = {54 65 72 6d 69 6e 61 74 65 50 72 6f 63 65 73 73 } //1 TerminateProcess
		$a_01_3 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //1 OpenProcess
		$a_01_4 = {47 65 74 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 41 } //1 GetWindowsDirectoryA
		$a_01_5 = {47 65 74 54 65 6d 70 46 69 6c 65 4e 61 6d 65 41 } //1 GetTempFileNameA
		$a_01_6 = {47 65 74 54 65 6d 70 50 61 74 68 41 } //1 GetTempPathA
		$a_01_7 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 43 61 63 68 65 46 69 6c 65 41 } //1 URLDownloadToCacheFileA
		$a_01_8 = {5c 72 65 67 63 68 65 63 6b } //1 \regcheck
		$a_01_9 = {2f 73 70 61 6d 62 6f 74 } //2 /spambot
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*2) >=10
 
}