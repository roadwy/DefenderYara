
rule Trojan_Win32_Qakbot_AB_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d1 89 55 ?? a1 ?? ?? ?? ?? 03 45 ?? 8a 4d ?? 88 08 e9 90 0a 30 00 89 45 ?? 0f b6 0d ?? ?? ?? ?? 8b 55 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Qakbot_AB_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d0 4a a1 ?? ?? ?? ?? 89 10 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 2b d8 4b 6a 00 e8 ?? ?? ?? ?? 2b d8 4b 6a 00 e8 ?? ?? ?? ?? 03 d8 a1 ?? ?? ?? ?? 33 18 89 1d ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 02 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}