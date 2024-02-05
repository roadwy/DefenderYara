
rule Trojan_Win32_Lokibot_SG_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 55 fc 03 55 f8 90 05 0a 01 90 8a 03 90 05 0a 01 90 34 90 01 01 90 05 0a 01 90 88 02 90 05 0a 01 90 8d 45 f8 e8 90 01 04 90 05 0a 01 90 43 4e 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Lokibot_SG_MTB_2{
	meta:
		description = "Trojan:Win32/Lokibot.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 c4 e8 53 56 57 33 c0 55 68 90 01 04 64 ff 30 64 89 20 e8 44 0e f9 ff 89 45 fc 90 02 05 8b 45 fc 89 45 f8 90 02 04 8d 45 e8 50 e8 90 02 10 8b 45 f8 3b 45 fc 0f 90 00 } //01 00 
		$a_03_1 = {8b d3 8b c6 e8 90 01 02 ff ff 46 81 fe 90 01 02 00 00 75 90 00 } //01 00 
		$a_03_2 = {8d 55 e8 8d 45 f0 e8 90 01 02 ff ff 8b c8 90 00 } //00 00 
		$a_00_3 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}