
rule Trojan_Win32_Lokibot_AU_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.AU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {00 00 5a 80 34 01 90 01 01 41 39 d1 75 f7 05 90 01 02 00 00 ff e0 90 0a 30 00 e8 90 01 01 ff ff ff b8 90 01 03 00 31 c9 68 90 01 02 00 00 5a 90 00 } //01 00 
		$a_03_1 = {53 51 8b d8 54 6a 40 68 90 01 02 00 00 53 e8 90 01 04 50 e8 90 01 04 5a 5b c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Lokibot_AU_MTB_2{
	meta:
		description = "Trojan:Win32/Lokibot.AU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_81_0 = {57 53 63 72 69 70 74 2e 53 6c 65 65 70 } //01 00  WScript.Sleep
		$a_81_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_81_2 = {73 63 68 74 61 73 6b 73 20 2f 52 75 6e 20 2f 54 4e } //01 00  schtasks /Run /TN
		$a_81_3 = {72 65 67 20 64 65 6c 65 74 65 20 68 6b 63 75 5c 45 6e 76 69 72 6f 6e 6d 65 6e 74 20 2f 76 20 77 69 6e 64 69 72 20 2f 66 20 26 26 20 52 45 4d } //01 00  reg delete hkcu\Environment /v windir /f && REM
		$a_81_4 = {72 65 67 20 61 64 64 20 68 6b 63 75 5c 45 6e 76 69 72 6f 6e 6d 65 6e 74 20 2f 76 20 77 69 6e 64 69 72 20 2f 64 20 22 63 6d 64 20 2f 63 20 73 74 61 72 74 } //01 00  reg add hkcu\Environment /v windir /d "cmd /c start
		$a_81_5 = {73 63 20 63 6f 6e 66 69 67 20 57 69 6e 44 65 66 65 6e 64 20 73 74 61 72 74 3d 20 64 69 73 61 62 6c 65 64 } //01 00  sc config WinDefend start= disabled
		$a_81_6 = {72 65 67 20 61 64 64 20 22 48 4b 4c 4d 5c 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 53 65 6e 73 65 22 20 2f 76 20 22 53 74 61 72 74 22 20 2f 74 20 22 52 45 47 5f 44 57 4f 52 44 22 20 2f 64 20 22 34 22 20 2f 66 } //01 00  reg add "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /v "Start" /t "REG_DWORD" /d "4" /f
		$a_81_7 = {72 65 67 20 61 64 64 20 22 48 4b 4c 4d 5c 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 57 64 4e 69 73 53 76 63 22 20 2f 76 20 22 53 74 61 72 74 22 20 2f 74 20 22 52 45 47 5f 44 57 4f 52 44 22 20 2f 64 20 22 34 22 20 2f 66 } //01 00  reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t "REG_DWORD" /d "4" /f
		$a_81_8 = {72 65 67 20 61 64 64 20 22 48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 22 20 2f 76 20 22 44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 22 20 2f 74 20 22 52 45 47 5f 44 57 4f 52 44 22 20 2f 64 20 22 31 22 20 2f 66 } //01 00  reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t "REG_DWORD" /d "1" /f
		$a_81_9 = {72 65 67 20 61 64 64 20 22 48 4b 4c 4d 5c 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 57 69 6e 44 65 66 65 6e 64 22 20 2f 76 20 22 53 74 61 72 74 22 20 2f 74 20 22 52 45 47 5f 44 57 4f 52 44 22 20 2f 64 20 22 34 22 20 2f 66 } //00 00  reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t "REG_DWORD" /d "4" /f
		$a_00_10 = {5d 04 00 00 37 1e 04 } //80 5c 
	condition:
		any of ($a_*)
 
}