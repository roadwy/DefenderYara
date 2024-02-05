
rule Trojan_Win32_Danabot_RF_MTB{
	meta:
		description = "Trojan:Win32/Danabot.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 f6 39 74 24 90 01 01 7e 90 01 01 53 8b 1d 90 01 04 55 8b 2d 90 01 04 57 8b 7c 24 90 01 01 8d 64 24 90 01 01 6a 00 ff d5 6a 00 ff d3 e8 90 01 04 30 04 3e 6a 00 ff d3 6a 90 00 } //01 00 
		$a_03_1 = {0f af 44 24 90 01 01 c7 04 24 1b 3d 26 00 81 04 24 a8 61 00 00 8b 0c 24 8b 54 24 90 01 01 03 c8 89 0a 59 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}