
rule Trojan_Win32_Qakbot_AO_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 4b 6a 00 e8 [0-04] 03 d8 6a 00 e8 [0-04] 03 d8 6a 00 e8 [0-04] 03 d8 6a 00 e8 [0-04] 03 d8 a1 [0-04] 33 18 89 1d [0-04] 6a 00 e8 [0-04] 8b d8 03 1d [0-04] 6a 00 e8 [0-04] 03 d8 6a 00 e8 [0-04] 03 d8 6a 00 e8 [0-04] 03 d8 a1 [0-04] 89 18 a1 [0-04] 83 c0 04 a3 [0-04] 33 c0 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_AO_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.AO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 41 cd 05 ee (3a|66 3b) ?? 90 13 e8 ?? ?? ?? ?? 59 (3a|66 3b) ?? 90 13 89 45 ?? 68 45 1b 13 42 (3a|66 3b) ?? 90 13 e8 ?? ?? ?? ?? 59 (3a|66 3b) ?? 90 13 89 45 ?? 68 43 ac 95 0e (3a|66 3b) } //1
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}