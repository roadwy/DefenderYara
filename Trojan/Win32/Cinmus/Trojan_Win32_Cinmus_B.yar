
rule Trojan_Win32_Cinmus_B{
	meta:
		description = "Trojan:Win32/Cinmus.B,SIGNATURE_TYPE_PEHSTR_EXT,2a 00 2a 00 07 00 00 0a 00 "
		
	strings :
		$a_00_0 = {48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 } //0a 00  HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
		$a_00_1 = {44 6f 77 6e 6c 6f 61 64 4d 44 35 } //0a 00  DownloadMD5
		$a_00_2 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //0a 00  CreateMutexA
		$a_01_3 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //01 00  InternetReadFile
		$a_00_4 = {67 73 2e 63 68 6e 73 79 73 74 65 6d 2e 63 6f 6d } //01 00  gs.chnsystem.com
		$a_00_5 = {73 73 6c 2e 63 68 6e 73 79 73 74 65 6d 2e 63 6f 6d } //01 00  ssl.chnsystem.com
		$a_00_6 = {6d 73 6c 2e 63 68 6e 73 79 73 74 65 6d 2e 63 6f 6d 20 } //00 00  msl.chnsystem.com 
	condition:
		any of ($a_*)
 
}