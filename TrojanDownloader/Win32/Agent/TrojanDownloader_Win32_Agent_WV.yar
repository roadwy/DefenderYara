
rule TrojanDownloader_Win32_Agent_WV{
	meta:
		description = "TrojanDownloader:Win32/Agent.WV,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 0a 00 00 03 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 79 75 70 73 65 61 72 63 68 2e 63 6f 6d } //01 00  http://yupsearch.com
		$a_00_1 = {2f 73 69 6c 65 6e 74 5f 69 6e 73 74 61 6c 6c 2e 65 78 65 } //01 00  /silent_install.exe
		$a_00_2 = {2f 73 69 64 65 62 2e 65 78 65 } //01 00  /sideb.exe
		$a_00_3 = {5c 25 6c 64 25 64 2e 65 78 65 } //02 00  \%ld%d.exe
		$a_00_4 = {49 6e 6a 65 63 74 6f 72 4c 6f 61 64 65 72 4d 4d 46 } //02 00  InjectorLoaderMMF
		$a_00_5 = {57 4d 5f 48 4f 4f 4b 53 50 59 5f 52 4b } //01 00  WM_HOOKSPY_RK
		$a_00_6 = {48 6f 6f 6b 50 72 6f 63 } //01 00  HookProc
		$a_00_7 = {44 6f 77 6e 6c 6f 61 64 52 65 6d 6f 74 65 } //01 00  DownloadRemote
		$a_00_8 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_01_9 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //00 00  SetWindowsHookExA
	condition:
		any of ($a_*)
 
}