
rule Trojan_Win32_Qakbot_SAH_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {88 02 42 47 83 c6 ?? 8b c6 83 d1 ?? 0b c1 75 } //1
		$a_03_1 = {8b c1 83 e0 ?? 8a 44 30 ?? 30 04 11 41 3b cf 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}