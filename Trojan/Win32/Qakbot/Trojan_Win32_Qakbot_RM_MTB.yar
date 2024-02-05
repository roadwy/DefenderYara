
rule Trojan_Win32_Qakbot_RM_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c4 18 89 05 90 01 04 b8 26 00 00 00 03 05 90 01 04 83 e8 4f 33 05 90 01 04 03 c0 81 e8 36 52 e0 7d 03 c0 83 e8 1f 33 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_RM_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {05 98 d9 0b 01 88 54 24 90 01 01 8a d3 2a d1 89 07 80 c2 13 a3 90 01 04 0f b7 c9 83 c7 04 0f b6 c2 0f af c1 66 03 44 24 90 01 01 83 6c 24 90 01 01 01 0f b7 c8 89 90 01 01 24 4c 0f b7 c8 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_RM_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 c1 38 10 00 00 8b 55 90 01 01 8b 02 2b c1 8b 4d 90 01 01 89 01 90 00 } //01 00 
		$a_03_1 = {8b d2 33 15 90 01 04 c7 05 90 01 04 00 00 00 00 8b d2 01 15 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 8b e5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}