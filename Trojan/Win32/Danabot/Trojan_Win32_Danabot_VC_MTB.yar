
rule Trojan_Win32_Danabot_VC_MTB{
	meta:
		description = "Trojan:Win32/Danabot.VC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b f7 c7 05 90 02 0a c1 ee 90 01 01 03 c7 03 f1 0f 57 c0 8b cf 66 0f 13 05 90 01 04 c1 e1 90 01 01 03 ca 33 c8 81 3d 90 02 0a 89 4c 24 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Danabot_VC_MTB_2{
	meta:
		description = "Trojan:Win32/Danabot.VC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 0f 57 c0 66 0f 13 05 90 01 04 8b 45 90 01 01 03 45 90 01 01 89 45 90 01 01 8b 4d 90 01 01 33 4d 90 01 01 89 4d 90 01 01 8b 55 90 01 01 33 55 90 01 01 89 55 90 01 01 8b 45 90 01 01 2b 45 90 01 01 89 45 90 00 } //01 00 
		$a_03_1 = {51 c7 45 fc 90 01 04 81 6d fc 90 01 04 2d f3 32 05 00 81 6d fc 90 01 04 81 45 fc 90 01 04 8b 45 fc 8b e5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}