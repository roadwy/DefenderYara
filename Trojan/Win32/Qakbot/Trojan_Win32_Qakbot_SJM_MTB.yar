
rule Trojan_Win32_Qakbot_SJM_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SJM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {bb 10 00 00 00 03 e3 eb 90 01 01 f7 f6 8b 45 90 01 01 0f b6 44 10 90 01 01 66 3b c9 74 90 01 01 33 c8 8b 45 90 01 01 03 45 90 01 01 e9 90 01 04 0f b6 08 8b 45 90 01 01 33 d2 66 3b f6 0f 84 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}