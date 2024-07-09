
rule Trojan_Win32_Qakbot_SJM_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SJM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {bb 10 00 00 00 03 e3 eb ?? f7 f6 8b 45 ?? 0f b6 44 10 ?? 66 3b c9 74 ?? 33 c8 8b 45 ?? 03 45 ?? e9 ?? ?? ?? ?? 0f b6 08 8b 45 ?? 33 d2 66 3b f6 0f 84 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}