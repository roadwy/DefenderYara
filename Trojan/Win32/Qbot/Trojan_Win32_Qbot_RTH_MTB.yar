
rule Trojan_Win32_Qbot_RTH_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 10 8b 45 90 01 01 05 8a a5 08 00 03 45 90 01 01 8b 15 90 01 04 31 02 83 45 90 01 01 04 83 05 90 01 04 04 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_RTH_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b a5 08 00 c7 05 90 02 05 64 00 00 00 90 00 } //01 00 
		$a_03_1 = {89 02 33 c0 a3 90 01 04 a1 90 01 04 83 c0 04 03 05 90 01 04 a3 90 01 04 a1 90 01 04 83 c0 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_RTH_MTB_3{
	meta:
		description = "Trojan:Win32/Qbot.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {05 8a a5 08 00 03 45 90 01 01 8b 55 90 01 01 31 02 6a 00 e8 90 01 04 8b d8 83 c3 04 6a 00 e8 90 01 04 2b d8 01 5d 90 01 01 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_RTH_MTB_4{
	meta:
		description = "Trojan:Win32/Qbot.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {05 8a a5 08 00 03 45 90 01 01 03 d8 68 cf 0d 00 00 6a 00 e8 90 01 04 03 d8 68 cf 0d 00 00 90 00 } //01 00 
		$a_03_1 = {68 cf 0d 00 00 6a 00 e8 90 01 04 03 d8 8b 45 90 01 01 31 18 8d 85 90 01 04 33 c9 ba 3c 00 00 00 e8 90 01 04 8d 85 68 ff ff ff 33 c9 ba 3c 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}