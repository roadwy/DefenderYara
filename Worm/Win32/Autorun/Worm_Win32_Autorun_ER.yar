
rule Worm_Win32_Autorun_ER{
	meta:
		description = "Worm:Win32/Autorun.ER,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 22 20 2f 76 20 22 53 74 61 72 74 20 50 61 67 65 22 20 2f 74 20 52 45 47 5f 45 58 50 41 4e 44 5f 53 5a 20 2f 64 } //01 00  HKCU\Software\Microsoft\Internet Explorer\Main" /v "Start Page" /t REG_EXPAND_SZ /d
		$a_01_1 = {48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 43 6f 6e 74 72 6f 6c 20 50 61 6e 65 6c 22 20 2f 76 20 22 48 6f 6d 65 50 61 67 65 22 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 30 30 30 30 30 30 30 31 20 2f 66 } //01 00  HKCU\Software\Policies\Microsoft\Internet Explorer\Control Panel" /v "HomePage" /t REG_DWORD /d 00000001 /f
		$a_01_2 = {61 75 74 6f 72 75 6e 2e 69 6e 66 } //01 00  autorun.inf
		$a_01_3 = {5b 41 75 74 6f 52 75 6e 5d } //01 00  [AutoRun]
		$a_01_4 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d 47 48 4f 2e 65 78 65 } //01 00  shell\open\Command=GHO.exe
		$a_01_5 = {48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 56 20 63 72 73 73 73 20 2f 54 20 52 45 47 5f 53 5a 20 2f 44 } //01 00  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /V crsss /T REG_SZ /D
		$a_01_6 = {48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 57 69 6e 64 6f 77 73 55 70 64 61 74 65 20 2f 76 20 44 69 73 61 62 6c 65 57 69 6e 64 6f 77 73 55 70 64 61 74 65 41 63 63 65 73 73 20 2f 74 20 52 45 47 5f 64 77 6f 72 64 20 2f 64 20 30 30 30 30 30 30 30 31 20 2f 66 } //01 00  HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_dword /d 00000001 /f
		$a_01_7 = {48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 5c 46 6f 6c 64 65 72 5c 48 69 64 64 65 6e 5c 53 48 4f 57 41 4c 4c 20 2f 76 20 43 68 65 63 6b 65 64 56 61 6c 75 65 20 2f 74 20 52 45 47 5f 64 77 6f 72 64 20 2f 64 20 30 30 30 30 30 30 30 30 20 2f 66 } //01 00  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL /v CheckedValue /t REG_dword /d 00000000 /f
		$a_01_8 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 74 72 79 } //01 00  if exist "%s" goto try
		$a_01_9 = {64 65 6c 20 25 30 } //00 00  del %0
	condition:
		any of ($a_*)
 
}