
rule Trojan_Win32_Zbot_BAE_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 04 00 "
		
	strings :
		$a_03_0 = {03 4d f8 8b 11 03 55 f8 a1 90 02 04 03 45 f8 89 10 8b 4d f8 81 c1 e9 03 00 00 8b 15 90 02 04 03 55 f8 33 0a a1 90 02 04 03 45 f8 89 08 eb 90 00 } //04 00 
		$a_03_1 = {03 4d f4 8b 01 03 45 f4 03 55 f4 89 02 8b 45 f8 89 45 f0 c7 45 fc 86 7f 00 00 8b 05 90 02 04 89 45 ec 8b 55 08 03 55 f4 8b 02 33 45 ec 8b 4d 08 03 4d f4 89 01 eb 90 00 } //01 00 
		$a_01_2 = {2e 72 6f 70 66 } //00 00 
	condition:
		any of ($a_*)
 
}