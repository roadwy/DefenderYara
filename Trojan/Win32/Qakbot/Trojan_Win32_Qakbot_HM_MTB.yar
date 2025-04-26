
rule Trojan_Win32_Qakbot_HM_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.HM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c8 8b 45 ?? eb ?? 55 8b ec eb ?? 8b 45 ?? 0f b6 04 10 eb ?? 51 bb ?? ?? ?? ?? eb ?? 8b 45 ?? 03 45 ?? eb ?? 40 89 45 ?? eb ?? 99 f7 7d ?? eb ?? 03 45 ?? 88 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}