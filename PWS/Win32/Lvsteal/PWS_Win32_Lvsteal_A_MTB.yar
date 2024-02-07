
rule PWS_Win32_Lvsteal_A_MTB{
	meta:
		description = "PWS:Win32/Lvsteal.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2e 00 2e 00 0e 00 00 14 00 "
		
	strings :
		$a_03_0 = {47 33 f6 8d 45 ec 50 8b d6 03 d2 42 b9 02 00 00 00 8b 45 fc e8 90 01 04 8b 4d ec 8d 45 f0 ba 90 01 04 e8 90 01 04 8b 45 f0 ba 20 00 00 00 e8 90 01 04 8b d8 8b 45 f8 e8 90 01 04 85 c0 7e 1d 8b 45 f8 e8 90 01 04 50 8b c6 5a 8b ca 99 f7 f9 42 8b 45 f8 8a 44 10 ff 32 c3 8b d8 8d 45 e8 8b d3 e8 90 01 04 8b 55 e8 8b 45 f4 e8 90 01 04 8b 45 f4 46 4f 75 86 90 00 } //14 00 
		$a_01_1 = {5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c 70 72 6f 66 69 6c 65 73 2e 69 6e 69 } //01 00  \Mozilla\Firefox\profiles.ini
		$a_01_2 = {47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //01 00  Google\Chrome\User Data\Default\Login Data
		$a_01_3 = {5c 6c 6f 67 69 6e 73 2e 6a 73 6f 6e } //01 00  \logins.json
		$a_01_4 = {6c 76 69 6e 67 20 68 6f 73 74 6e 61 6d 65 20 25 73 } //01 00  lving hostname %s
		$a_01_5 = {5c 5c 2e 5c 53 4d 41 52 54 56 53 44 } //01 00  \\.\SMARTVSD
		$a_01_6 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //01 00  \\.\PhysicalDrive0
		$a_01_7 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 72 6f 64 75 63 74 4e 61 6d 65 } //01 00  SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName
		$a_01_8 = {5c 70 72 65 66 73 2e 6a 73 } //01 00  \prefs.js
		$a_01_9 = {5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4d 6f 7a 69 6c 6c 61 20 46 69 72 65 66 6f 78 5c 66 69 72 65 66 6f 78 2e 65 78 65 } //01 00  \Program Files\Mozilla Firefox\firefox.exe
		$a_01_10 = {5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 20 28 78 38 36 29 5c 4d 6f 7a 69 6c 6c 61 20 46 69 72 65 66 6f 78 5c 66 69 72 65 66 6f 78 2e 65 78 65 } //01 00  \Program Files (x86)\Mozilla Firefox\firefox.exe
		$a_01_11 = {5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //01 00  \Program Files\Internet Explorer\iexplore.exe
		$a_01_12 = {5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 20 28 78 38 36 29 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //01 00  \Program Files (x86)\Internet Explorer\iexplore.exe
		$a_01_13 = {43 68 72 6f 6d 65 5f 57 69 64 67 65 74 57 69 6e 5f } //00 00  Chrome_WidgetWin_
	condition:
		any of ($a_*)
 
}