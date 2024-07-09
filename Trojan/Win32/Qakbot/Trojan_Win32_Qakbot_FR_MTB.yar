
rule Trojan_Win32_Qakbot_FR_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.FR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 83 e0 ?? 8a 04 10 32 04 1f 88 04 39 47 83 ee ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_FR_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.FR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 18 8b 45 c4 03 45 a4 89 45 a0 8b 45 d8 8b 00 33 45 a0 89 45 a0 6a 00 e8 ?? ?? ?? ?? 8b 5d a0 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 d8 89 18 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}