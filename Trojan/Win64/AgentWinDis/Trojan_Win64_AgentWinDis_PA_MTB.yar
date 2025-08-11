
rule Trojan_Win64_AgentWinDis_PA_MTB{
	meta:
		description = "Trojan:Win64/AgentWinDis.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 4d 73 4d 70 45 6e 67 2e 65 78 65 20 3e 6e 75 6c 20 32 3e 26 31 } //1 taskkill /f /im MsMpEng.exe >nul 2>&1
		$a_01_1 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 20 3e 6e 75 6c 20 32 3e 26 31 } //2 vssadmin delete shadows /all /quiet >nul 2>&1
		$a_01_2 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 63 6f 6d 6d 61 6e 64 20 22 53 65 74 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 44 69 73 61 62 6c 65 52 65 61 6c 74 69 6d 65 4d 6f 6e 69 74 6f 72 69 6e 67 20 24 74 72 75 65 } //1 powershell -command "Set-MpPreference -DisableRealtimeMonitoring $true
		$a_01_3 = {73 68 75 74 64 6f 77 6e 20 2f 73 20 2f 66 20 2f 74 20 30 20 2f 63 20 22 57 69 6e 64 6f 77 73 20 55 70 64 61 74 65 } //1 shutdown /s /f /t 0 /c "Windows Update
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}