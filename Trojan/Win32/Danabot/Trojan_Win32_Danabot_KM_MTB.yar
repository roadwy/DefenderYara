
rule Trojan_Win32_Danabot_KM_MTB{
	meta:
		description = "Trojan:Win32/Danabot.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 d3 03 d0 81 e2 ff 00 00 00 81 3d 90 01 04 8a 08 00 00 89 15 90 01 04 75 90 09 19 00 8b 0d 90 01 04 0f be 86 90 01 04 8a 99 90 01 04 03 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Danabot_KM_MTB_2{
	meta:
		description = "Trojan:Win32/Danabot.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {d3 e2 89 74 24 90 01 01 89 54 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 a1 90 01 04 3d 1a 0c 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Danabot_KM_MTB_3{
	meta:
		description = "Trojan:Win32/Danabot.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 03 55 90 01 01 89 55 90 01 01 8b 45 90 01 01 31 45 90 01 01 2b 75 90 01 01 8b 45 90 01 01 d1 6d 90 01 01 29 45 90 01 01 ff 4d 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Danabot_KM_MTB_4{
	meta:
		description = "Trojan:Win32/Danabot.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_00_0 = {83 c0 7b 89 04 24 b8 f9 cd 03 00 01 04 24 83 2c 24 7b 8b 04 24 8a 04 08 88 04 0a 59 c3 } //02 00 
		$a_02_1 = {0f b6 d3 03 ca a3 90 01 04 81 e1 ff 00 00 00 8a 81 90 01 04 30 04 37 83 6d 90 01 01 01 8b 75 90 01 01 85 f6 7d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}