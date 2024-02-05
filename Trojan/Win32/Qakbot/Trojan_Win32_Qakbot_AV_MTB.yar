
rule Trojan_Win32_Qakbot_AV_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {03 d8 8b 45 d8 33 18 89 5d a0 8b 45 a0 8b 55 d8 89 02 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4 8b 45 d8 83 c0 04 03 45 a4 89 45 d8 8b 45 a8 3b 45 cc 0f } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_AV_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.AV!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 55 fc 5a d3 c0 8a fc 8a e6 d3 cb ff 4d fc 75 f3 29 c9 0b 0c e4 83 c4 04 89 4d f8 83 e1 00 31 d9 83 e0 00 31 c8 8b 4d f8 aa 49 75 } //00 00 
	condition:
		any of ($a_*)
 
}