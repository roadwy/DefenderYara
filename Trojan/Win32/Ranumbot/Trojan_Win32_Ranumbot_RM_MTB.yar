
rule Trojan_Win32_Ranumbot_RM_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 4c 24 90 01 01 8d 0c 32 89 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 31 4c 24 90 01 01 81 3d 90 01 04 f5 03 00 00 c7 05 90 01 04 36 06 ea e9 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ranumbot_RM_MTB_2{
	meta:
		description = "Trojan:Win32/Ranumbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 e0 01 45 90 01 01 c7 05 90 01 04 36 06 ea e9 8b 90 01 01 e4 33 90 01 02 89 90 01 02 c7 90 02 09 8b 45 90 00 } //01 00 
		$a_03_1 = {c1 e9 05 89 4d 90 01 01 8b 45 90 01 01 01 45 90 01 01 81 3d 90 01 04 c6 0e 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ranumbot_RM_MTB_3{
	meta:
		description = "Trojan:Win32/Ranumbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e9 05 89 4d 90 01 01 8b 45 90 01 01 01 45 90 01 01 c7 05 90 01 04 36 06 ea e9 8b 55 90 01 01 33 55 90 01 01 89 55 90 01 01 83 3d 90 02 08 75 90 00 } //01 00 
		$a_03_1 = {8b 45 e0 01 45 ec c7 05 90 01 04 36 06 ea e9 8b 90 01 01 e4 33 90 01 01 f0 89 90 01 01 e4 90 02 0c 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}