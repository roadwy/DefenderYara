
rule Trojan_Win32_Qakbot_HJ_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.HJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 40 04 8b 4d f8 eb ?? f7 f6 0f b6 44 15 ?? 3a d2 74 ?? 53 5e 3a e4 74 ?? 8d 44 01 ?? 89 45 ?? e9 ?? ?? ?? ?? 33 d2 bb 04 00 00 00 3a c0 74 ?? 33 c8 8b 45 ?? eb ?? 89 45 ?? 8b 45 ?? 3a ed 74 } //1
		$a_03_1 = {33 c8 8b 45 ?? e9 ?? ?? ?? ?? 0f b6 4c 05 ?? 8b 45 ?? 66 3b e4 74 ?? 8d 44 01 ?? 89 45 ?? e9 ?? ?? ?? ?? 8b 40 ?? 8b 4d ?? eb ?? 40 89 45 ?? e9 ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 66 3b ed 74 ?? 33 d2 bb 04 00 00 00 3a d2 74 ?? a5 bb ?? ?? ?? ?? e9 ?? ?? ?? ?? f7 f6 0f b6 44 15 ?? 3a c9 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}