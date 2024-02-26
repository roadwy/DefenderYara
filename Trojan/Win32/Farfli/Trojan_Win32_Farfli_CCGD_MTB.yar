
rule Trojan_Win32_Farfli_CCGD_MTB{
	meta:
		description = "Trojan:Win32/Farfli.CCGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 43 20 20 72 65 67 65 64 69 74 20 2f 73 20 55 61 63 2e 72 65 67 } //01 00  cmd /C  regedit /s Uac.reg
		$a_01_1 = {25 73 5c 25 64 2e 62 61 6b } //01 00  %s\%d.bak
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {63 68 72 6f 6d 65 2e 65 78 65 } //01 00  chrome.exe
		$a_01_4 = {66 69 72 65 66 6f 78 2e 65 78 65 } //01 00  firefox.exe
		$a_01_5 = {51 51 42 72 6f 77 73 65 72 2e 65 78 65 } //01 00  QQBrowser.exe
		$a_01_6 = {4e 4f 44 33 32 } //01 00  NOD32
		$a_01_7 = {41 76 61 73 74 } //01 00  Avast
		$a_01_8 = {41 76 69 72 61 } //01 00  Avira
		$a_01_9 = {4b 37 54 53 65 63 75 72 69 74 79 2e 65 78 65 } //01 00  K7TSecurity.exe
		$a_01_10 = {51 55 49 43 4b 20 48 45 41 4c } //01 00  QUICK HEAL
		$a_01_11 = {48 41 52 44 57 41 52 45 5c 44 45 53 43 52 49 50 54 49 4f 4e 5c 53 79 73 74 65 6d 5c 43 65 6e 74 72 61 6c 50 72 6f 63 65 73 73 6f 72 5c 30 } //00 00  HARDWARE\DESCRIPTION\System\CentralProcessor\0
	condition:
		any of ($a_*)
 
}