
rule Trojan_Win32_Qakbot_PU_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 bb 04 00 00 00 53 90 13 5e f7 f6 0f b6 44 ?? a8 66 3b c9 90 13 33 c8 8b 45 ?? 88 4c ?? ac 90 13 8b 45 ?? 90 13 40 89 45 ?? 83 7d ?? 04 90 13 8b 45 ?? 89 45 ?? 8b 45 ?? e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}