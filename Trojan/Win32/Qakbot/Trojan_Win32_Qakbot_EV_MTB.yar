
rule Trojan_Win32_Qakbot_EV_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.EV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d e4 2b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 33 f1 89 35 ?? ?? ?? ?? 8d 8d 64 ff ff ff e8 ?? ?? ?? ?? 0f b6 15 ?? ?? ?? ?? 33 55 f0 89 55 f0 0f b6 05 ?? ?? ?? ?? 8b 4d f0 2b c8 89 4d f0 0f b6 15 ?? ?? ?? ?? 8b 45 f0 2b c2 89 45 f0 8b 0d ?? ?? ?? ?? 03 4d ec 8a 55 f0 88 11 e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}