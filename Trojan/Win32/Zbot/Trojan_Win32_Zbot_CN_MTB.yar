
rule Trojan_Win32_Zbot_CN_MTB{
	meta:
		description = "Trojan:Win32/Zbot.CN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 d9 41 f7 e1 89 85 90 02 04 33 85 90 02 04 8b 95 90 02 04 89 02 83 c6 08 83 45 f8 08 83 c6 fc 83 45 f8 fc 83 3e 00 75 94 90 00 } //01 00 
		$a_01_1 = {89 f9 89 da d3 fa 29 d7 8b 55 e8 29 fa 89 55 } //00 00 
	condition:
		any of ($a_*)
 
}