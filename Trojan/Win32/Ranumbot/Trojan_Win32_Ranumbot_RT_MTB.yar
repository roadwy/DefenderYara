
rule Trojan_Win32_Ranumbot_RT_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 55 e0 89 55 90 01 01 c7 90 01 05 36 06 ea e9 8b 90 01 02 81 90 01 05 ca f9 15 16 01 90 01 05 8b 90 01 02 33 90 01 05 89 90 01 02 81 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ranumbot_RT_MTB_2{
	meta:
		description = "Trojan:Win32/Ranumbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c5 c1 e8 05 c7 05 90 01 04 84 10 d6 cb c7 05 90 01 04 ff ff ff ff 89 44 24 90 01 01 8b 84 24 90 01 04 01 44 24 90 01 01 81 3d 90 01 04 c6 0e 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ranumbot_RT_MTB_3{
	meta:
		description = "Trojan:Win32/Ranumbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 f6 85 ff 7e 90 01 01 8b 2d 90 01 04 8d 64 24 90 01 01 e8 90 01 04 30 04 1e 83 ff 19 75 90 01 01 6a 00 6a 00 6a 00 6a 00 ff d5 46 3b f7 7c 90 01 01 81 ff 71 11 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ranumbot_RT_MTB_4{
	meta:
		description = "Trojan:Win32/Ranumbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 e0 01 45 90 01 01 c7 05 90 01 04 36 06 ea e9 8b 90 01 01 e4 33 90 01 01 f0 89 90 01 01 e4 c7 90 02 09 8b 90 01 02 01 90 01 05 8b 90 01 02 33 05 90 01 04 89 90 01 02 83 3d 90 02 08 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ranumbot_RT_MTB_5{
	meta:
		description = "Trojan:Win32/Ranumbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 4d e0 89 4d 90 01 01 c7 05 90 01 04 36 06 ea e9 8b 90 01 02 81 05 90 02 08 01 90 01 05 8b 90 01 02 33 15 90 01 04 89 90 01 02 c7 05 90 00 } //01 00 
		$a_03_1 = {03 55 e0 89 55 ec c7 05 90 01 04 36 06 ea e9 8b 90 01 02 81 90 01 05 ca f9 15 16 01 90 01 05 8b 90 01 02 33 90 01 05 89 90 01 02 c7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}