
rule TrojanDownloader_Win32_Agent_AGA{
	meta:
		description = "TrojanDownloader:Win32/Agent.AGA,SIGNATURE_TYPE_PEHSTR_EXT,2c 00 2c 00 09 00 00 "
		
	strings :
		$a_00_0 = {67 68 30 73 74 } //10 gh0st
		$a_00_1 = {6a 00 73 00 6d 00 69 00 74 00 68 00 40 00 77 00 6f 00 72 00 6c 00 64 00 2e 00 63 00 6f 00 6d 00 } //10 jsmith@world.com
		$a_00_2 = {5c 64 6c 6c 63 61 63 68 65 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //10 \dllcache\svchost.exe
		$a_00_3 = {43 3a 5c 54 65 73 74 46 69 6c 65 73 5c 77 69 6e 2e 69 6e 69 } //10 C:\TestFiles\win.ini
		$a_00_4 = {5c 73 79 73 74 65 6d 2e 62 61 6b } //1 \system.bak
		$a_00_5 = {5c 73 79 73 74 65 6d 2e 6c 6f 67 } //1 \system.log
		$a_00_6 = {57 69 6e 45 78 65 63 } //1 WinExec
		$a_00_7 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_8 = {47 65 74 53 79 73 74 65 6d 44 69 72 65 63 74 6f 72 79 41 } //1 GetSystemDirectoryA
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_01_8  & 1)*1) >=44
 
}