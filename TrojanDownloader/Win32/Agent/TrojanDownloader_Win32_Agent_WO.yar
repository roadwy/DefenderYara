
rule TrojanDownloader_Win32_Agent_WO{
	meta:
		description = "TrojanDownloader:Win32/Agent.WO,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 0b 00 00 01 00 "
		
	strings :
		$a_00_0 = {26 61 3d 31 20 48 54 54 50 2f 31 2e 31 } //01 00  &a=1 HTTP/1.1
		$a_00_1 = {47 45 54 20 2f 64 6c 3f 77 3d } //01 00  GET /dl?w=
		$a_00_2 = {48 6f 73 74 3a 20 36 36 } //01 00  Host: 66
		$a_00_3 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 } //02 00  User-Agent: 
		$a_00_4 = {36 36 2e 31 31 37 2e 33 37 2e 37 } //02 00  66.117.37.7
		$a_00_5 = {2f 61 75 74 6f 64 65 74 65 63 74 2e 65 78 65 } //01 00  /autodetect.exe
		$a_01_6 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //01 00  InternetReadFile
		$a_01_7 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //01 00  InternetOpenUrlA
		$a_01_8 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //01 00  InternetOpenA
		$a_00_9 = {47 65 74 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 41 } //01 00  GetWindowsDirectoryA
		$a_00_10 = {47 65 74 54 65 6d 70 50 61 74 68 41 } //00 00  GetTempPathA
	condition:
		any of ($a_*)
 
}