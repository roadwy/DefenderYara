
rule Trojan_Win64_Convagent_ARAX_MTB{
	meta:
		description = "Trojan:Win64/Convagent.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 e9 c1 fa 04 8b c2 c1 e8 1f 03 d0 0f be c2 6b d0 36 0f b6 c1 2a c2 04 38 41 30 00 ff c1 4d 8d 40 01 83 f9 0f 7c d4 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win64_Convagent_ARAX_MTB_2{
	meta:
		description = "Trojan:Win64/Convagent.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 63 68 74 61 73 6b 73 20 2f 64 65 6c 65 74 65 20 2f 74 6e 20 22 57 69 6e 64 6f 77 73 55 70 64 61 74 65 22 20 2f 66 20 3e 6e 75 6c 20 32 3e 26 31 } //2 schtasks /delete /tn "WindowsUpdate" /f >nul 2>&1
		$a_01_1 = {2d 44 69 73 61 62 6c 65 52 65 61 6c 74 69 6d 65 4d 6f 6e 69 74 6f 72 69 6e 67 } //2 -DisableRealtimeMonitoring
		$a_01_2 = {2d 44 69 73 61 62 6c 65 53 63 72 69 70 74 53 63 61 6e 6e 69 6e 67 } //2 -DisableScriptScanning
		$a_01_3 = {2d 44 69 73 61 62 6c 65 50 72 69 76 61 63 79 4d 6f 64 65 } //2 -DisablePrivacyMode
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}