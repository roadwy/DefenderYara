
rule Trojan_Win32_Qakbot_SAC_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 54 24 34 83 c2 ?? 8b 4c 24 ?? 8b 81 ?? ?? ?? ?? 0f af 81 ?? ?? ?? ?? 8b 7c 24 ?? 31 f8 39 c2 8b 6c 24 } //1
		$a_01_1 = {d1 5a 41 00 59 d1 8b 00 95 33 cd 00 44 b5 72 00 } //1
		$a_01_2 = {be 53 47 00 ba 57 53 00 ff 96 46 00 09 be 80 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}