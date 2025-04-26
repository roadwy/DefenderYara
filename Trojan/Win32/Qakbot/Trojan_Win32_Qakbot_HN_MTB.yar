
rule Trojan_Win32_Qakbot_HN_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.HN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 10 ?? 3a ff 74 ?? 03 45 ?? 88 08 e9 ?? ?? ?? ?? e9 ?? ?? ?? ?? 5e f7 f6 66 3b c9 74 ?? 83 c3 ?? 53 66 3b c9 74 ?? 21 5d ?? 8d 45 ?? eb ?? 53 58 3a e4 74 ?? c1 e0 ?? 8b 44 05 ?? 3a ed 74 ?? 33 c8 8b 45 ?? 66 3b c9 74 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}