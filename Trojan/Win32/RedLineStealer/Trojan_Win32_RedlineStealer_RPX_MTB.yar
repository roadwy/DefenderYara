
rule Trojan_Win32_RedlineStealer_RPX_MTB{
	meta:
		description = "Trojan:Win32/RedlineStealer.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b f3 33 d8 8b c6 f6 17 8b f0 8b c0 33 de 33 c0 8b c6 33 f3 8b f3 33 c0 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_RedlineStealer_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/RedlineStealer.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 91 a4 00 00 00 83 c2 08 8b 75 cc 8d 4d 80 31 ff 89 34 24 89 54 24 04 89 4c 24 08 c7 44 24 0c 04 00 00 00 c7 44 24 10 00 00 00 00 ff d0 83 ec 14 8b 85 64 ff ff ff 8b 4d e0 8b 49 50 8b 55 e0 } //00 00 
	condition:
		any of ($a_*)
 
}