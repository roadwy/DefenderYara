
rule Trojan_Win64_AVKill_A_MTB{
	meta:
		description = "Trojan:Win64/AVKill.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 6f 77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 20 22 24 77 73 68 65 6c 6c 3d 4e 65 77 2d 4f 62 6a 65 63 74 20 2d 43 6f 6d 4f 62 6a 65 63 74 20 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 3b 20 24 77 73 68 65 6c 6c 2e 53 65 6e 64 4b 65 79 73 28 27 } //2 Powershell -Command "$wshell=New-Object -ComObject wscript.shell; $wshell.SendKeys('
		$a_01_1 = {50 6f 77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 20 22 47 65 74 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 } //2 Powershell -Command "Get-MpPreference
		$a_01_2 = {72 65 67 20 61 64 64 20 22 48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 20 53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 5c 4e 6f 74 69 66 69 63 61 74 69 6f 6e 73 22 20 2f 76 20 22 44 69 73 61 62 6c 65 4e 6f 74 69 66 69 63 61 74 69 6f 6e 73 22 20 2f 74 20 72 65 67 5f 44 57 4f 52 44 20 2f 64 20 22 31 22 20 2f 66 } //2 reg add "HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t reg_DWORD /d "1" /f
		$a_01_3 = {72 65 67 20 61 64 64 20 22 48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 20 53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 5c 53 79 73 74 72 61 79 22 20 2f 76 20 22 48 69 64 65 53 79 73 74 72 61 79 22 20 2f 74 20 72 65 67 5f 44 57 4f 52 44 20 2f 64 20 22 31 22 20 2f 66 } //2 reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" /v "HideSystray" /t reg_DWORD /d "1" /f
		$a_01_4 = {72 65 67 20 61 64 64 20 22 48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 5c 53 63 61 6e 22 20 2f 76 20 22 44 69 73 61 62 6c 65 53 63 61 6e 6e 69 6e 67 4d 61 70 70 65 64 4e 65 74 77 6f 72 6b 44 72 69 76 65 73 46 6f 72 46 75 6c 6c 53 63 61 6e 22 20 2f 74 20 72 65 67 5f 44 57 4f 52 44 20 2f 64 20 22 31 22 20 2f 66 } //2 reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableScanningMappedNetworkDrivesForFullScan" /t reg_DWORD /d "1" /f
		$a_01_5 = {72 65 67 20 61 64 64 20 22 48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 5c 53 63 61 6e 22 20 2f 76 20 22 44 69 73 61 62 6c 65 53 63 61 6e 6e 69 6e 67 4e 65 74 77 6f 72 6b 46 69 6c 65 73 22 20 2f 74 20 72 65 67 5f 44 57 4f 52 44 20 2f 64 20 22 31 22 20 2f 66 } //2 reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableScanningNetworkFiles" /t reg_DWORD /d "1" /f
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}