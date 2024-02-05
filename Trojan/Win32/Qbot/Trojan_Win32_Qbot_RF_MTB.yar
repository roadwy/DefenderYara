
rule Trojan_Win32_Qbot_RF_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2d 80 0d 00 00 03 05 90 01 04 a3 90 01 04 a1 90 01 04 03 05 90 01 04 8b 15 90 01 04 31 02 83 05 90 01 04 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 dc 03 45 b0 03 45 bc 8b 15 90 01 04 31 02 68 90 01 04 e8 90 02 64 83 45 90 01 01 04 83 05 90 01 04 04 8b 45 90 01 01 3b 45 90 01 01 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_RF_MTB_3{
	meta:
		description = "Trojan:Win32/Qbot.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 3b 11 00 00 6a 00 e8 90 01 04 03 d8 68 3b 11 00 00 6a 00 e8 90 01 04 03 d8 8b 45 90 01 01 31 18 68 90 01 04 e8 90 01 04 68 90 00 } //01 00 
		$a_03_1 = {05 8a a5 08 00 03 45 90 01 01 03 d8 68 3b 11 00 00 6a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_RF_MTB_4{
	meta:
		description = "Trojan:Win32/Qbot.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {01 02 8b 45 90 01 01 05 8a a5 08 00 03 45 90 01 01 8b 55 90 01 01 31 02 68 90 01 04 e8 90 01 04 68 90 01 04 e8 90 01 04 68 90 01 04 e8 90 01 04 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_RF_MTB_5{
	meta:
		description = "Trojan:Win32/Qbot.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c0 89 45 90 01 01 c7 45 90 01 01 8a a5 08 00 8b 45 90 01 01 3b 45 90 01 01 73 90 00 } //01 00 
		$a_03_1 = {8b d8 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 03 d8 e8 90 01 04 2b d8 a1 90 01 04 31 18 e8 90 01 04 8b d8 a1 90 01 04 83 c0 04 03 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_RF_MTB_6{
	meta:
		description = "Trojan:Win32/Qbot.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {05 8a a5 08 00 03 45 90 01 01 03 d8 68 cf 0d 00 00 6a 00 e8 90 01 04 03 d8 68 cf 0d 00 00 6a 00 e8 90 01 04 03 d8 68 cf 0d 00 00 6a 00 e8 90 01 04 03 d8 68 90 00 } //01 00 
		$a_03_1 = {03 d8 68 cf 0d 00 00 6a 00 e8 90 01 04 03 d8 8b 45 90 01 01 31 18 6a 00 e8 90 01 04 6a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}