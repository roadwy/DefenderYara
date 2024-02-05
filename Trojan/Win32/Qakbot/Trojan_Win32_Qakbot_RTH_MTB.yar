
rule Trojan_Win32_Qakbot_RTH_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 b8 93 29 8b 4c 24 90 01 01 8b 54 24 90 01 01 66 c7 44 24 90 01 01 92 a6 66 8b 74 24 90 01 01 6b c9 48 01 ca 89 54 24 90 01 01 c7 84 24 90 01 04 a2 91 9f 8e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_RTH_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 00 03 05 90 01 04 03 d8 6a 00 e8 90 01 04 2b d8 a1 90 01 04 89 18 6a 00 e8 90 01 04 8b d8 a1 90 01 04 03 05 90 01 04 03 d8 6a 00 e8 90 01 04 2b d8 a1 90 01 04 31 18 83 05 90 01 04 04 83 05 90 01 04 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}