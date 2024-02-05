
rule Trojan_Win32_Ranumbot_RW_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 c7 05 90 01 04 36 06 ea e9 8b 4d 90 01 01 33 4d 90 01 01 89 4d 90 01 01 83 3d 90 02 06 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ranumbot_RW_MTB_2{
	meta:
		description = "Trojan:Win32/Ranumbot.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 e0 01 45 90 01 01 c7 05 90 01 04 36 06 ea e9 8b 45 90 01 01 81 05 90 01 04 ca f9 15 16 01 05 90 01 04 8b 90 01 02 33 90 01 05 89 90 01 02 c7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ranumbot_RW_MTB_3{
	meta:
		description = "Trojan:Win32/Ranumbot.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 89 44 24 90 01 01 03 ce 89 54 24 90 01 01 8b 84 24 90 01 04 01 44 24 90 01 01 31 4c 24 90 01 01 81 3d 90 01 04 f5 03 00 00 c7 05 90 01 04 36 06 ea e9 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ranumbot_RW_MTB_4{
	meta:
		description = "Trojan:Win32/Ranumbot.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 e0 01 90 01 01 ec c7 05 90 01 04 36 06 ea e9 8b 90 01 01 e4 33 90 01 01 f0 89 90 01 01 e4 8b 45 e4 50 8d 90 01 01 ec 51 e8 90 01 04 8b 90 01 02 2b 90 01 02 89 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}