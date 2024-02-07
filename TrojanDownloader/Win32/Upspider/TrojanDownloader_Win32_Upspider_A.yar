
rule TrojanDownloader_Win32_Upspider_A{
	meta:
		description = "TrojanDownloader:Win32/Upspider.A,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 5c 7b 42 30 42 36 37 38 44 38 2d 45 43 42 33 2d 34 46 44 36 2d 41 38 44 37 2d 39 46 30 46 36 43 30 33 43 35 46 46 7d } //01 00  Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{B0B678D8-ECB3-4FD6-A8D7-9F0F6C03C5FF}
		$a_01_1 = {75 70 73 70 69 64 65 72 2e 63 6f 6d } //01 00  upspider.com
		$a_01_2 = {5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 44 43 42 } //01 00  \WINDOWS\system32\DCB
		$a_01_3 = {73 79 73 74 65 6d 33 32 5c 64 6c 30 37 2e 64 6c 6c } //01 00  system32\dl07.dll
		$a_01_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_01_5 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00  DllRegisterServer
	condition:
		any of ($a_*)
 
}