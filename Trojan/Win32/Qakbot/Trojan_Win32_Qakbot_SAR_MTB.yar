
rule Trojan_Win32_Qakbot_SAR_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {88 08 8b 45 ?? 66 ?? ?? 74 ?? 83 e8 ?? 8b 4d ?? 83 d9 ?? eb ?? 40 89 45 ?? 8b 45 ?? 3a db 74 } //1
		$a_03_1 = {0f b6 08 66 ?? ?? 74 ?? 8b 45 ?? 0f b6 44 10 ?? 33 c8 3a c0 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}