
rule Trojan_Win32_DropperAgent_PA_MTB{
	meta:
		description = "Trojan:Win32/DropperAgent.PA!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 65 67 2e 65 78 65 20 41 44 44 20 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 20 2f 76 20 64 69 73 61 62 6c 65 74 61 73 6b 6d 67 72 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 31 20 2f 66 } //01 00  reg.exe ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v disabletaskmgr /t REG_DWORD /d 1 /f
		$a_01_1 = {72 65 67 2e 65 78 65 20 41 44 44 20 48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 20 2f 76 20 45 6e 61 62 6c 65 4c 55 41 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 30 20 2f 66 } //01 00  reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
		$a_01_2 = {72 65 67 2e 65 78 65 20 41 44 44 20 48 4b 43 55 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 41 63 74 69 76 65 44 65 73 6b 74 6f 70 20 2f 76 20 4e 6f 43 68 61 6e 67 69 6e 67 57 61 6c 6c 50 61 70 65 72 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 31 20 2f 66 } //01 00  reg.exe ADD HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop /v NoChangingWallPaper /t REG_DWORD /d 1 /f
		$a_01_3 = {72 65 67 2e 65 78 65 20 41 44 44 20 48 4b 4c 4d 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 76 20 43 68 65 63 6b 46 6f 72 55 70 64 61 74 65 73 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 25 68 6f 6d 65 64 72 69 76 65 25 5c 43 4f 56 49 44 2d 31 39 5c 55 70 64 61 74 65 2e 76 62 73 20 2f 66 } //01 00  reg.exe ADD HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v CheckForUpdates /t REG_SZ /d %homedrive%\COVID-19\Update.vbs /f
		$a_01_4 = {72 65 67 2e 65 78 65 20 41 44 44 20 48 4b 4c 4d 5c 73 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 76 20 47 6f 6f 64 62 79 65 50 43 21 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 25 68 6f 6d 65 64 72 69 76 65 25 5c 43 4f 56 49 44 2d 31 39 5c 65 6e 64 2e 65 78 65 20 2f 66 } //01 00  reg.exe ADD HKLM\software\Microsoft\Windows\CurrentVersion\Run /v GoodbyePC! /t REG_SZ /d %homedrive%\COVID-19\end.exe /f
		$a_01_5 = {79 00 6f 00 75 00 72 00 20 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 68 00 61 00 73 00 20 00 69 00 6e 00 66 00 65 00 63 00 74 00 65 00 64 00 20 00 62 00 79 00 20 00 63 00 6f 00 72 00 6f 00 6e 00 61 00 76 00 69 00 72 00 75 00 73 00 } //01 00  your computer has infected by coronavirus
		$a_01_6 = {59 6f 75 72 20 43 6f 6d 70 75 74 65 72 20 48 61 73 20 42 65 65 6e 20 54 72 61 73 68 65 64 } //00 00  Your Computer Has Been Trashed
	condition:
		any of ($a_*)
 
}