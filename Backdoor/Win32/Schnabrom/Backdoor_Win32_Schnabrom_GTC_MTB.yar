
rule Backdoor_Win32_Schnabrom_GTC_MTB{
	meta:
		description = "Backdoor:Win32/Schnabrom.GTC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 63 72 65 65 6e 73 61 76 65 72 2e 73 63 72 } //01 00  Screensaver.scr
		$a_01_1 = {2f 43 20 74 69 6d 65 6f 75 74 20 35 20 26 20 64 65 6c 20 2f 46 20 2f 51 } //01 00  /C timeout 5 & del /F /Q
		$a_01_2 = {52 48 4a 76 63 45 56 34 5a 57 4d 3d } //01 00  RHJvcEV4ZWM=
		$a_01_3 = {4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  Microsoft\Windows\CurrentVersion\Run
		$a_80_4 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74 } //SELECT * FROM AntiVirusProduct  01 00 
		$a_01_5 = {2f 63 6f 6d 6d 61 6e 64 73 2e 70 68 70 } //01 00  /commands.php
		$a_01_6 = {5c 64 65 73 6b 74 6f 70 2e 69 6e 69 } //01 00  \desktop.ini
		$a_01_7 = {46 43 3a 5c 57 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 53 48 45 4c 4c 33 32 2e 64 6c 6c } //00 00  FC:\Windows\system32\SHELL32.dll
	condition:
		any of ($a_*)
 
}