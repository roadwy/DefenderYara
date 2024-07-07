
rule TrojanDownloader_Win32_Agent_AJI{
	meta:
		description = "TrojanDownloader:Win32/Agent.AJI,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 46 69 6c 65 45 78 74 73 5c 2e } //1 Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.
		$a_00_1 = {2f 6d 73 77 6f 72 64 2f 73 65 61 72 63 68 2f } //1 /msword/search/
		$a_00_2 = {2f 65 78 65 6c 2f 64 6f 77 6e 6c 6f 61 64 2f } //1 /exel/download/
		$a_00_3 = {2f 77 69 6e 64 6f 77 2f 73 74 6f 70 2f } //1 /window/stop/
		$a_00_4 = {2f 70 61 73 63 61 6c 2f 66 69 6e 64 2f } //1 /pascal/find/
		$a_00_5 = {41 64 6a 75 73 74 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73 } //1 AdjustTokenPrivileges
		$a_00_6 = {2f 78 70 2f 72 75 6e 2f } //1 /xp/run/
		$a_00_7 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_00_8 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //1 InternetReadFile
		$a_00_9 = {53 68 65 6c 6c 45 78 65 63 75 74 65 45 78 41 } //1 ShellExecuteExA
		$a_01_10 = {56 42 53 63 72 69 70 74 00 3d 00 68 74 74 70 3a 2f 2f } //1 䉖捓楲瑰㴀栀瑴㩰⼯
		$a_00_11 = {26 72 65 73 74 61 72 74 3d } //1 &restart=
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_01_10  & 1)*1+(#a_00_11  & 1)*1) >=12
 
}