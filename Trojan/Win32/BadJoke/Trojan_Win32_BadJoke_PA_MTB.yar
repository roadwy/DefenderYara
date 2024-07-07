
rule Trojan_Win32_BadJoke_PA_MTB{
	meta:
		description = "Trojan:Win32/BadJoke.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 vssadmin delete shadows /all /quiet
		$a_01_1 = {43 6f 6e 67 72 61 74 75 6c 61 74 69 6f 6e 73 2e 74 78 74 } //1 Congratulations.txt
		$a_01_2 = {65 78 63 75 73 65 20 6d 65 20 6d 61 74 65 20 79 6f 75 20 69 6e 73 74 61 6c 6c 65 64 20 6d 61 6c 77 61 72 65 20 6f 6e 20 74 68 65 20 73 79 73 74 65 6d } //1 excuse me mate you installed malware on the system
		$a_01_3 = {59 00 65 00 61 00 68 00 20 00 59 00 65 00 61 00 68 00 20 00 69 00 74 00 73 00 20 00 34 00 32 00 30 00 20 00 74 00 69 00 6d 00 65 00 } //1 Yeah Yeah its 420 time
		$a_01_4 = {23 00 4d 00 41 00 4b 00 45 00 4d 00 41 00 4c 00 57 00 41 00 52 00 45 00 47 00 52 00 45 00 41 00 54 00 41 00 47 00 41 00 49 00 4e 00 } //1 #MAKEMALWAREGREATAGAIN
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
rule Trojan_Win32_BadJoke_PA_MTB_2{
	meta:
		description = "Trojan:Win32/BadJoke.PA!MTB,SIGNATURE_TYPE_PEHSTR,12 00 12 00 0b 00 00 "
		
	strings :
		$a_01_0 = {2f 43 20 64 65 6c 20 25 73 79 73 74 65 6d 72 6f 6f 74 25 20 2f 46 20 2f 53 20 2f 51 } //5 /C del %systemroot% /F /S /Q
		$a_01_1 = {6f 67 6f 20 70 6f 73 6f 73 69 20 68 75 79 } //5 ogo pososi huy
		$a_01_2 = {72 65 67 20 61 64 64 20 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 20 2f 76 20 44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 31 20 2f 66 } //2 reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_DWORD /d 1 /f
		$a_01_3 = {72 65 67 20 61 64 64 20 48 4b 43 55 53 6f 66 74 77 61 72 65 4d 69 63 72 6f 73 6f 66 74 57 69 6e 64 6f 77 73 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 50 6f 6c 69 63 69 65 73 53 79 73 74 65 6d 20 2f 76 20 44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 31 20 2f 66 } //2 reg add HKCUSoftwareMicrosoftWindowsCurrentVersionPoliciesSystem /v DisableTaskMgr /t REG_DWORD /d 1 /f
		$a_01_4 = {74 65 73 74 5c 69 6d 6c 6f 78 5c 69 6d 6c 6f 78 5c 52 65 6c 65 61 73 65 5c 69 6d 6c 6f 78 2e 70 64 62 } //2 test\imlox\imlox\Release\imlox.pdb
		$a_01_5 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e 20 22 57 69 6e 64 6f 77 73 55 70 64 61 74 65 76 31 22 20 2f 74 72 20 22 43 3a 5c 6d 79 61 70 70 2e 65 78 65 22 20 2f 73 63 20 6f 6e 6c 6f 67 6f 6e } //2 schtasks /create /tn "WindowsUpdatev1" /tr "C:\myapp.exe" /sc onlogon
		$a_01_6 = {6f 70 65 6e 20 22 43 3a 5c 54 45 4d 50 5c 73 6f 6d 65 2e 6d 70 33 22 20 74 79 70 65 20 6d 70 65 67 76 69 64 65 6f 20 61 6c 69 61 73 20 65 72 72 6f 72 6d 73 67 } //2 open "C:\TEMP\some.mp3" type mpegvideo alias errormsg
		$a_01_7 = {6f 70 65 6e 20 22 43 3a 5c 54 45 4d 50 5c 73 6f 6d 65 2e 6d 70 33 22 20 74 79 70 65 20 6d 70 65 67 76 69 64 65 6f 20 61 6c 69 61 73 20 6a 75 73 74 73 6e 64 } //2 open "C:\TEMP\some.mp3" type mpegvideo alias justsnd
		$a_01_8 = {70 6c 61 79 20 65 72 72 6f 72 6d 73 67 20 72 65 70 65 61 74 } //1 play errormsg repeat
		$a_01_9 = {70 6c 61 79 20 6a 75 73 74 73 6e 64 20 72 65 70 65 61 74 } //1 play justsnd repeat
		$a_01_10 = {73 6f 6d 65 2e 70 6e 67 } //1 some.png
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=18
 
}