
rule Trojan_Win32_Qakbot_HG_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.HG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 4c 05 ?? 8b 45 ?? 33 d2 66 3b ff 74 ?? bb ?? ?? ?? ?? 53 5e 66 3b f6 74 ?? 8b 4d ?? 03 48 ?? 89 4d ?? 66 3b d2 74 ?? f7 f6 0f b6 44 15 ?? 33 c8 e9 ?? ?? ?? ?? ff 75 ?? 8b 45 ?? ff 70 ?? 3a f6 74 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}