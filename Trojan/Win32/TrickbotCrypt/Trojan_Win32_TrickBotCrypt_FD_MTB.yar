
rule Trojan_Win32_TrickBotCrypt_FD_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.FD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {2f 63 20 70 6f 77 65 72 73 68 65 6c 6c 20 53 65 74 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 44 69 73 61 62 6c 65 52 65 61 6c 74 69 6d 65 4d 6f 6e 69 74 6f 72 69 6e 67 20 24 74 72 75 65 } //1 /c powershell Set-MpPreference -DisableRealtimeMonitoring $true
		$a_81_1 = {2f 63 20 73 63 20 73 74 6f 70 20 57 69 6e 44 65 66 65 6e 64 } //1 /c sc stop WinDefend
		$a_81_2 = {44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 } //1 DisableAntiSpyware
		$a_81_3 = {44 69 73 61 62 6c 65 53 63 61 6e 4f 6e 52 65 61 6c 74 69 6d 65 45 6e 61 62 6c 65 } //1 DisableScanOnRealtimeEnable
		$a_81_4 = {44 69 73 61 62 6c 65 4f 6e 41 63 63 65 73 73 50 72 6f 74 65 63 74 69 6f 6e } //1 DisableOnAccessProtection
		$a_81_5 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_81_6 = {43 50 50 64 65 62 75 67 48 6f 6f 6b } //1 CPPdebugHook
		$a_81_7 = {5c 6c 47 42 78 73 61 5c 6a 6b 68 6a 6b 67 5c 68 67 68 6a 5c 74 65 6d 70 2e 64 61 74 } //1 \lGBxsa\jkhjkg\hghj\temp.dat
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}