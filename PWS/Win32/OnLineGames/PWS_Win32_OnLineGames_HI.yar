
rule PWS_Win32_OnLineGames_HI{
	meta:
		description = "PWS:Win32/OnLineGames.HI,SIGNATURE_TYPE_PEHSTR,12 00 12 00 0f 00 00 03 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //03 00  Software\Microsoft\Windows NT\CurrentVersion\Winlogon
		$a_01_1 = {53 46 43 44 69 73 61 62 6c 65 } //03 00  SFCDisable
		$a_01_2 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //01 00  InternetReadFile
		$a_01_3 = {2f 6b 69 63 6b 6f 75 74 2e 61 73 70 } //01 00  /kickout.asp
		$a_01_4 = {61 63 74 3d 6f 6e 6c 69 6e 65 26 4e 61 6d 65 3d 25 73 } //01 00  act=online&Name=%s
		$a_01_5 = {25 73 5c 73 6f 73 6f 2e 62 6d 70 } //01 00  %s\soso.bmp
		$a_01_6 = {25 73 5c 73 6f 73 6f 2e 64 61 74 } //01 00  %s\soso.dat
		$a_01_7 = {25 73 4a 61 63 6b 73 6f 6e 2e 62 61 74 } //01 00  %sJackson.bat
		$a_01_8 = {5c 73 74 61 72 74 5c 75 73 65 72 73 65 74 74 69 6e 67 2e 69 6e 69 } //01 00  \start\usersetting.ini
		$a_01_9 = {62 6c 69 6e 6b } //01 00  blink
		$a_01_10 = {73 65 63 6f 6e 64 70 61 73 73 } //01 00  secondpass
		$a_01_11 = {70 61 73 73 77 6f 72 64 } //01 00  password
		$a_01_12 = {64 6e 66 2e 65 78 65 } //01 00  dnf.exe
		$a_01_13 = {71 71 6c 6f 67 69 6e 2e 65 78 65 } //01 00  qqlogin.exe
		$a_01_14 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e } //00 00  Accept-Language: zh-cn
	condition:
		any of ($a_*)
 
}