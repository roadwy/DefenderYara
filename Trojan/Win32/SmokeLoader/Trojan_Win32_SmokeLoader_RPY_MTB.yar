
rule Trojan_Win32_SmokeLoader_RPY_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {01 44 24 18 8b 44 24 18 89 44 24 20 8b 4c 24 1c 8b c6 d3 e8 8b 4c 24 10 03 c5 89 44 24 14 33 44 24 20 33 c8 8d 44 24 28 89 4c 24 10 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_SmokeLoader_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 d4 01 45 fc 89 5d f4 8b 45 e8 01 45 f4 8b 45 d0 90 01 45 f4 8b 45 f4 89 45 ec 8b 4d f0 8b c6 d3 e8 8b 4d ec 31 4d fc 03 45 cc } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_SmokeLoader_RPY_MTB_3{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 85 0e fc ff ff 33 c6 85 11 fc ff ff 6e c6 85 06 fc ff ff 54 c6 85 13 fc ff ff 70 c6 85 0f fc ff ff 32 c6 85 01 fc ff ff 72 c6 85 09 fc ff ff 6c c6 85 15 fc ff ff 68 c6 85 14 fc ff ff 73 c6 85 04 fc ff ff 74 c6 85 12 fc ff ff 61 c6 85 10 fc ff ff 53 c6 85 03 fc ff ff 61 c6 85 18 fc ff ff 00 } //00 00 
	condition:
		any of ($a_*)
 
}