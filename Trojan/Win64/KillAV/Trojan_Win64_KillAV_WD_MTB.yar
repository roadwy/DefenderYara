
rule Trojan_Win64_KillAV_WD_MTB{
	meta:
		description = "Trojan:Win64/KillAV.WD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e 20 22 25 73 5f 32 22 20 2f 74 72 20 22 25 73 22 20 2f 73 63 20 44 41 49 4c 59 20 2f 6d 6f 20 31 20 2f 66 20 3e 6e 75 6c 20 32 3e 26 31 } //1 schtasks /create /tn "%s_2" /tr "%s" /sc DAILY /mo 1 /f >nul 2>&1
		$a_81_1 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 20 22 53 65 74 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 44 69 73 61 62 6c 65 42 65 68 61 76 69 6f 72 4d 6f 6e 69 74 6f 72 69 6e 67 20 24 74 72 75 65 22 20 3e 6e 75 6c 20 32 3e 26 31 } //1 powershell -Command "Set-MpPreference -DisableBehaviorMonitoring $true" >nul 2>&1
		$a_81_2 = {47 6c 6f 62 61 6c 5c 48 49 54 4d 41 4e 5f 4d 55 54 45 58 } //1 Global\HITMAN_MUTEX
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}