
rule TrojanDownloader_Win32_Renos_gen_Z{
	meta:
		description = "TrojanDownloader:Win32/Renos.gen!Z,SIGNATURE_TYPE_PEHSTR_EXT,ffffffbb 0b ffffffbb 0b 09 00 00 "
		
	strings :
		$a_80_0 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 6d 69 67 68 74 20 62 65 20 61 74 20 72 69 73 6b } //Your computer might be at risk  1000
		$a_02_1 = {53 70 79 77 61 72 65 [0-ff] 44 65 74 65 63 74 65 64 } //1
		$a_02_2 = {56 69 72 75 73 [0-ff] 44 65 74 65 63 74 65 64 } //1
		$a_80_3 = {43 6c 69 63 6b 20 74 68 69 73 20 62 61 6c 6c 6f 6f 6e 20 74 6f 20 66 69 78 20 74 68 69 73 20 70 72 6f 62 6c 65 6d } //Click this balloon to fix this problem  1000
		$a_00_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1000 Software\Microsoft\Windows\CurrentVersion\Run
		$a_00_5 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
		$a_00_6 = {57 69 6e 45 78 65 63 } //1 WinExec
		$a_00_7 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_00_8 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //1 InternetReadFile
	condition:
		((#a_80_0  & 1)*1000+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_80_3  & 1)*1000+(#a_00_4  & 1)*1000+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=3003
 
}