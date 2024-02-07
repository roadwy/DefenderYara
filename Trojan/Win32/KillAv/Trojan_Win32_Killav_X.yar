
rule Trojan_Win32_Killav_X{
	meta:
		description = "Trojan:Win32/Killav.X,SIGNATURE_TYPE_PEHSTR,2a 00 2a 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 53 74 75 64 69 6f 5c 56 42 } //0a 00  Microsoft Visual Studio\VB
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //0a 00  URLDownloadToFileA
		$a_01_2 = {64 6f 77 6e 6c 6f 61 64 5f 70 72 6f 67 72 65 73 73 } //0a 00  download_progress
		$a_01_3 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 69 00 6d 00 20 00 } //01 00  taskkill /f /im 
		$a_01_4 = {63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 6e 00 65 00 74 00 20 00 73 00 74 00 6f 00 70 00 20 00 73 00 68 00 61 00 72 00 65 00 64 00 61 00 63 00 63 00 65 00 73 00 73 00 } //01 00  cmd /c net stop sharedaccess
		$a_01_5 = {67 00 6f 00 2e 00 63 00 6e 00 2f 00 66 00 64 00 2f 00 66 00 64 00 35 00 2f 00 66 00 64 00 } //01 00  go.cn/fd/fd5/fd
		$a_01_6 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 67 00 67 00 2e 00 70 00 77 00 } //01 00  http://gg.pw
		$a_01_7 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 46 00 6f 00 6e 00 74 00 73 00 5c 00 49 00 45 00 58 00 50 00 4c 00 4f 00 52 00 45 00 52 00 2e 00 45 00 58 00 45 00 } //00 00  C:\WINDOWS\Fonts\IEXPLORER.EXE
	condition:
		any of ($a_*)
 
}