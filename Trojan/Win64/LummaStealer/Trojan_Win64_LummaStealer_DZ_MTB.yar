
rule Trojan_Win64_LummaStealer_DZ_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.DZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {42 0f b6 04 27 4c 89 ef 44 8b 6d 98 0f b6 0c 1e 01 c1 0f b6 c1 48 8b 4d b0 0f b6 04 01 48 63 4d f0 48 8b 55 88 30 04 0a 44 8b 65 f0 41 83 c4 01 b8 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Trojan_Win64_LummaStealer_DZ_MTB_2{
	meta:
		description = "Trojan:Win64/LummaStealer.DZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 54 45 4d 50 5c 61 75 74 68 5f 6b 65 79 2e 64 61 74 } //1 C:\TEMP\auth_key.dat
		$a_01_1 = {53 74 61 72 74 20 49 6e 6a 65 63 74 69 6f 6e } //1 Start Injection
		$a_01_2 = {44 69 73 61 62 6c 65 52 65 61 6c 74 69 6d 65 4d 6f 6e 69 74 6f 72 69 6e 67 } //1 DisableRealtimeMonitoring
		$a_01_3 = {44 69 73 61 62 6c 65 42 65 68 61 76 69 6f 72 4d 6f 6e 69 74 6f 72 69 6e 67 } //1 DisableBehaviorMonitoring
		$a_01_4 = {44 69 73 61 62 6c 65 49 4f 41 56 50 72 6f 74 65 63 74 69 6f 6e } //1 DisableIOAVProtection
		$a_01_5 = {44 4c 4c 20 49 4e 4a 45 43 54 45 44 20 53 55 43 43 45 53 53 46 55 4c 4c 59 } //1 DLL INJECTED SUCCESSFULLY
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}