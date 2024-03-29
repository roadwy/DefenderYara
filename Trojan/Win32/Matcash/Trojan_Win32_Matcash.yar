
rule Trojan_Win32_Matcash{
	meta:
		description = "Trojan:Win32/Matcash,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 63 62 6f 6f 2e 63 6f 6d } //01 00  mcboo.com
		$a_00_1 = {73 65 61 72 63 68 2e 63 6f 6d 2d 63 6f 6d 2e 77 73 } //01 00  search.com-com.ws
		$a_00_2 = {61 66 66 69 6c 69 61 74 65 3d } //01 00  affiliate=
		$a_00_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_00_4 = {32 30 38 2e 36 37 2e 32 32 32 2e 32 32 32 } //01 00  208.67.222.222
		$a_00_5 = {25 73 55 70 64 61 74 65 57 6f 72 64 73 5c 25 } //00 00  %sUpdateWords\%
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Matcash_2{
	meta:
		description = "Trojan:Win32/Matcash,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 07 00 00 0a 00 "
		
	strings :
		$a_00_0 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //0a 00  InternetOpenUrlA
		$a_00_1 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //02 00  CreateMutexA
		$a_01_2 = {64 6f 77 6e 6c 6f 61 64 00 00 00 00 57 52 5c 6e 65 78 74 75 70 64 61 74 65 } //02 00 
		$a_01_3 = {70 61 69 64 00 00 00 00 57 52 5c 63 6f 6e 66 69 67 76 65 72 73 69 6f 6e } //02 00 
		$a_01_4 = {65 72 31 00 6e 6e 00 00 75 6e } //01 00 
		$a_00_5 = {76 65 72 73 69 6f 6e 00 6e 65 77 75 70 64 61 74 65 72 } //01 00  敶獲潩n敮畷摰瑡牥
		$a_00_6 = {77 61 69 74 00 00 00 00 65 78 65 63 75 74 65 00 68 69 64 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Matcash_3{
	meta:
		description = "Trojan:Win32/Matcash,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 19 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {47 6c 6f 62 61 6c 5c 7b 46 39 43 44 38 35 34 42 2d 32 43 38 42 2d 34 31 32 66 2d 38 46 31 33 2d 42 30 42 46 38 44 44 45 42 32 32 39 7d } //0a 00  Global\{F9CD854B-2C8B-412f-8F13-B0BF8DDEB229}
		$a_01_1 = {2f 77 74 64 2e 70 68 70 3f 75 69 64 3d 7b } //03 00  /wtd.php?uid={
		$a_01_2 = {49 6d 70 6f 73 73 69 62 6c 65 20 64 65 20 6c 69 72 65 20 6c 65 20 66 69 63 68 69 65 72 20 64 65 20 73 6f 72 74 69 65 } //03 00  Impossible de lire le fichier de sortie
		$a_01_3 = {6d 63 62 6f 6f 2e 63 6f 6d } //03 00  mcboo.com
		$a_01_4 = {6d 63 2d 00 74 65 2d 00 } //01 00  捭-整-
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 5c 43 4c 53 49 44 5c 7b } //01 00  Software\Classes\CLSID\{
		$a_01_6 = {53 79 73 74 65 6d 42 69 6f 73 44 61 74 65 } //00 00  SystemBiosDate
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Matcash_4{
	meta:
		description = "Trojan:Win32/Matcash,SIGNATURE_TYPE_PEHSTR_EXT,52 00 4f 00 0a 00 00 14 00 "
		
	strings :
		$a_01_0 = {7b 43 31 42 34 44 45 43 32 2d 32 36 32 33 2d 34 33 38 65 2d 39 43 41 32 2d 43 39 30 34 33 41 42 32 38 35 30 38 7d } //0a 00  {C1B4DEC2-2623-438e-9CA2-C9043AB28508}
		$a_00_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 54 6f 6f 6c 62 61 72 } //0a 00  Software\Microsoft\Internet Explorer\Toolbar
		$a_01_2 = {54 6f 6f 6c 42 61 72 2e 44 4c 4c } //0a 00  ToolBar.DLL
		$a_01_3 = {55 72 6c 45 73 63 61 70 65 41 } //0a 00  UrlEscapeA
		$a_01_4 = {42 61 6e 64 54 6f 6f 6c 42 61 72 52 65 66 6c 65 63 74 6f 72 43 74 72 6c } //0a 00  BandToolBarReflectorCtrl
		$a_01_5 = {42 61 6e 64 54 6f 6f 6c 42 61 72 43 74 72 6c } //03 00  BandToolBarCtrl
		$a_01_6 = {68 74 74 70 3a 2f 2f 62 61 62 65 6c 66 69 73 68 2e 61 6c 74 61 76 69 73 74 61 2e 63 6f 6d 2f } //03 00  http://babelfish.altavista.com/
		$a_01_7 = {68 74 74 70 3a 2f 2f 66 69 6e 61 6e 63 65 2e 79 61 68 6f 6f 2e 63 6f 6d 2f } //03 00  http://finance.yahoo.com/
		$a_01_8 = {68 74 74 70 3a 2f 2f 63 61 73 69 6e 6f 74 72 6f 70 65 7a 2e 63 6f 6d 2f } //03 00  http://casinotropez.com/
		$a_01_9 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 6f 6d 66 6d 2e 63 6f 6d } //00 00  http://www.comfm.com
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Matcash_5{
	meta:
		description = "Trojan:Win32/Matcash,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 07 00 00 0a 00 "
		
	strings :
		$a_02_0 = {2f 63 61 70 74 75 72 65 90 02 02 2f 90 02 06 2f 6d 63 61 73 68 2f 00 68 74 74 70 3a 2f 2f 00 63 6f 6d 90 00 } //02 00 
		$a_02_1 = {6e 61 6d 65 00 00 00 00 63 61 70 74 75 72 65 90 02 02 2e 6a 73 90 00 } //02 00 
		$a_00_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 00 00 66 69 72 73 74 } //02 00 
		$a_00_3 = {5c 54 65 6d 70 00 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e } //01 00 
		$a_00_4 = {25 32 2e 32 58 2d 25 32 2e 32 58 2d 25 32 2e 32 58 2d 25 32 2e 32 58 2d 25 32 2e 32 58 2d 25 32 2e 32 58 } //01 00  %2.2X-%2.2X-%2.2X-%2.2X-%2.2X-%2.2X
		$a_00_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
		$a_00_6 = {63 68 65 63 6b 2e 70 68 70 3f 6d 61 63 3d } //00 00  check.php?mac=
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Matcash_6{
	meta:
		description = "Trojan:Win32/Matcash,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 75 72 6c 6d 6f 6e 2e 64 6c 6c } //01 00  wurlmon.dll
		$a_01_1 = {6d 63 62 6f 6f 2e 63 6f 6d } //01 00  mcboo.com
		$a_01_2 = {57 69 6e 54 6f 75 63 68 2e 65 78 65 } //01 00  WinTouch.exe
		$a_01_3 = {77 69 6e 2d 74 6f 75 63 68 2e 63 6f 6d } //01 00  win-touch.com
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_01_6 = {43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 41 } //01 00  CreateDirectoryA
		$a_01_7 = {47 65 74 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 41 } //00 00  GetWindowsDirectoryA
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Matcash_7{
	meta:
		description = "Trojan:Win32/Matcash,SIGNATURE_TYPE_PEHSTR,08 00 06 00 07 00 00 03 00 "
		
	strings :
		$a_01_0 = {77 72 2e 6d 63 62 6f 6f 2e 63 6f 6d } //02 00  wr.mcboo.com
		$a_01_1 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 72 00 65 00 74 00 61 00 64 00 70 00 75 00 2e 00 65 00 78 00 65 } //02 00 
		$a_01_2 = {5c 72 65 74 61 64 70 75 } //01 00  \retadpu
		$a_01_3 = {64 6f 75 70 64 61 74 65 } //01 00  doupdate
		$a_01_4 = {64 6f 75 70 64 61 74 65 3d 3d 25 64 } //01 00  doupdate==%d
		$a_01_5 = {44 6f 77 6e 6c 6f 61 64 69 6e 67 20 66 69 6c 65 2e 2e 2e } //01 00  Downloading file...
		$a_01_6 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 75 00 70 00 64 00 61 00 74 00 65 00 72 } //00 00 
	condition:
		any of ($a_*)
 
}