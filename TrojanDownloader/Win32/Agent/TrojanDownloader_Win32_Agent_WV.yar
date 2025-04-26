
rule TrojanDownloader_Win32_Agent_WV{
	meta:
		description = "TrojanDownloader:Win32/Agent.WV,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 0a 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 79 75 70 73 65 61 72 63 68 2e 63 6f 6d } //3 http://yupsearch.com
		$a_00_1 = {2f 73 69 6c 65 6e 74 5f 69 6e 73 74 61 6c 6c 2e 65 78 65 } //1 /silent_install.exe
		$a_00_2 = {2f 73 69 64 65 62 2e 65 78 65 } //1 /sideb.exe
		$a_00_3 = {5c 25 6c 64 25 64 2e 65 78 65 } //1 \%ld%d.exe
		$a_00_4 = {49 6e 6a 65 63 74 6f 72 4c 6f 61 64 65 72 4d 4d 46 } //2 InjectorLoaderMMF
		$a_00_5 = {57 4d 5f 48 4f 4f 4b 53 50 59 5f 52 4b } //2 WM_HOOKSPY_RK
		$a_00_6 = {48 6f 6f 6b 50 72 6f 63 } //1 HookProc
		$a_00_7 = {44 6f 77 6e 6c 6f 61 64 52 65 6d 6f 74 65 } //1 DownloadRemote
		$a_00_8 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_9 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //1 SetWindowsHookExA
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_01_9  & 1)*1) >=11
 
}