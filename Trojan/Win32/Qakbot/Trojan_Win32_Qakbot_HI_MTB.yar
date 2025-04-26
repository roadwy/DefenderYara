
rule Trojan_Win32_Qakbot_HI_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.HI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 15 a0 33 c8 66 3b ff 74 ?? 8b 45 ?? 8b 40 ?? 3a db 74 ?? 8b 45 ?? 0f b6 4c 05 ?? 66 3b f6 74 ?? 8b 4d ?? 8d 44 01 ?? 3a c9 74 } //1
		$a_03_1 = {bb 04 00 00 00 53 66 3b c0 74 ?? 8b 45 ?? 33 d2 66 3b ff 74 ?? 89 45 ?? bb ?? ?? ?? ?? eb ?? 8b 45 ?? 88 4c 05 ?? e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}