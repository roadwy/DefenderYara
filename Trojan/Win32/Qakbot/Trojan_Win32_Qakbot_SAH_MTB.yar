
rule Trojan_Win32_Qakbot_SAH_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {88 02 42 47 83 c6 90 01 01 8b c6 83 d1 90 01 01 0b c1 75 90 00 } //1
		$a_03_1 = {8b c1 83 e0 90 01 01 8a 44 30 90 01 01 30 04 11 41 3b cf 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}