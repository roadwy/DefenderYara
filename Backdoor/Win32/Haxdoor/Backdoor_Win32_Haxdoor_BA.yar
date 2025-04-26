
rule Backdoor_Win32_Haxdoor_BA{
	meta:
		description = "Backdoor:Win32/Haxdoor.BA,SIGNATURE_TYPE_PEHSTR,ffffffbd 01 ffffffbd 01 11 00 00 "
		
	strings :
		$a_01_0 = {36 36 2e 32 34 36 2e 33 38 2e } //100 66.246.38.
		$a_01_1 = {5c 73 79 73 74 65 6d 33 32 5c 63 6f 6e 66 69 67 5c 53 41 4d } //100 \system32\config\SAM
		$a_01_2 = {54 4f 3a 20 48 41 58 4f 52 } //100 TO: HAXOR
		$a_01_3 = {4d 41 49 4c 20 46 52 4f 4d 3a 3c 25 73 3e } //100 MAIL FROM:<%s>
		$a_01_4 = {6b 6c 6f 67 2e 73 79 73 } //10 klog.sys
		$a_01_5 = {6f 75 74 70 6f 73 74 2e 65 78 65 } //10 outpost.exe
		$a_01_6 = {5c 77 69 6e 2e 63 6f 6d } //10 \win.com
		$a_01_7 = {6e 74 64 65 74 65 63 74 2e 63 6f 6d } //10 ntdetect.com
		$a_01_8 = {77 77 77 2e 70 72 6f 64 65 78 74 65 61 6d 2e 6e 65 74 } //1 www.prodexteam.net
		$a_01_9 = {63 6f 72 70 73 65 40 6d 61 69 6c 73 65 72 76 65 72 2e 72 75 } //1 corpse@mailserver.ru
		$a_01_10 = {45 78 69 74 57 69 6e 64 6f 77 73 45 78 } //1 ExitWindowsEx
		$a_01_11 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //1 CallNextHookEx
		$a_01_12 = {4e 74 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 NtQuerySystemInformation
		$a_01_13 = {47 45 54 20 2f 41 73 65 72 76 65 72 2e 70 68 70 3f 69 64 3d 25 73 26 70 61 72 61 6d 3d 25 75 20 48 54 54 50 2f 31 2e 31 } //1 GET /Aserver.php?id=%s&param=%u HTTP/1.1
		$a_01_14 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5c 4e 6f 74 69 66 79 5c 70 64 78 } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\pdx
		$a_01_15 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 41 70 70 20 50 61 74 68 73 5c 37 2d 7a 69 70 43 66 67 2e 65 78 65 } //1 Software\Microsoft\Windows\CurrentVersion\App Paths\7-zipCfg.exe
		$a_01_16 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 41 70 70 20 50 61 74 68 73 5c 57 69 6e 52 61 72 2e 65 78 65 } //1 Software\Microsoft\Windows\CurrentVersion\App Paths\WinRar.exe
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*100+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1) >=445
 
}