
rule Trojan_Win32_Phorpiex_SBR_MSR{
	meta:
		description = "Trojan:Win32/Phorpiex.SBR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 5f 00 5f 00 20 00 26 00 20 00 5f 00 5f 00 5c 00 44 00 72 00 69 00 76 00 65 00 4d 00 67 00 72 00 2e 00 65 00 78 00 65 00 20 00 26 00 20 00 65 00 78 00 69 00 74 00 } //1 /c start __ & __\DriveMgr.exe & exit
		$a_01_1 = {46 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 50 00 6f 00 6c 00 69 00 63 00 79 00 5c 00 53 00 74 00 61 00 6e 00 64 00 61 00 72 00 64 00 50 00 72 00 6f 00 66 00 69 00 6c 00 65 00 5c 00 41 00 75 00 74 00 68 00 6f 00 72 00 69 00 7a 00 65 00 64 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 73 00 5c 00 4c 00 69 00 73 00 74 00 } //1 FirewallPolicy\StandardProfile\AuthorizedApplications\List
		$a_01_2 = {25 00 75 00 73 00 65 00 72 00 70 00 72 00 6f 00 66 00 69 00 6c 00 65 00 25 00 } //1 %userprofile%
		$a_01_3 = {77 6f 72 6d 2e 74 6f 70 } //1 worm.top
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win32_Phorpiex_SBR_MSR_2{
	meta:
		description = "Trojan:Win32/Phorpiex.SBR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 74 73 72 76 31 2e 77 73 } //5 http://tsrv1.ws
		$a_01_1 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 53 00 63 00 61 00 6e 00 4f 00 6e 00 52 00 65 00 61 00 6c 00 74 00 69 00 6d 00 65 00 45 00 6e 00 61 00 62 00 6c 00 65 00 } //1 DisableScanOnRealtimeEnable
		$a_01_2 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 4f 00 6e 00 41 00 63 00 63 00 65 00 73 00 73 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 } //1 DisableOnAccessProtection
		$a_01_3 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 42 00 65 00 68 00 61 00 76 00 69 00 6f 00 72 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 69 00 6e 00 67 00 } //1 DisableBehaviorMonitoring
		$a_01_4 = {46 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 44 00 69 00 73 00 61 00 62 00 6c 00 65 00 4e 00 6f 00 74 00 69 00 66 00 79 00 } //1 FirewallDisableNotify
		$a_01_5 = {41 00 6e 00 74 00 69 00 56 00 69 00 72 00 75 00 73 00 4f 00 76 00 65 00 72 00 72 00 69 00 64 00 65 00 } //1 AntiVirusOverride
		$a_01_6 = {46 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 4f 00 76 00 65 00 72 00 72 00 69 00 64 00 65 00 } //1 FirewallOverride
		$a_01_7 = {2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 5f 00 5f 00 20 00 26 00 20 00 5f 00 5f 00 5c 00 44 00 72 00 69 00 76 00 65 00 4d 00 67 00 72 00 2e 00 65 00 78 00 65 00 20 00 26 00 20 00 65 00 78 00 69 00 74 00 } //1 /c start __ & __\DriveMgr.exe & exit
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}