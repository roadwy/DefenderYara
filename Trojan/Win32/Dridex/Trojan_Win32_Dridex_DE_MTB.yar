
rule Trojan_Win32_Dridex_DE_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {89 4c 24 50 83 f8 6a 89 44 24 24 0f 84 90 01 04 e9 90 01 04 8b 44 24 30 8d 65 fc 5e 5d c3 a1 90 01 04 0f b6 00 3d b8 00 00 00 0f 84 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_DE_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 14 16 01 d1 35 90 01 04 89 45 90 01 01 89 c8 99 8b 4d 90 01 01 f7 f9 8b 75 90 01 01 89 16 8b 55 90 01 01 8b 0a 8b 55 90 01 01 8b 12 0f b6 0c 0a 8b 16 8b 75 90 01 01 8b 36 0f b6 14 16 31 d1 88 cb 8b 4d 90 01 01 8b 11 8b 75 90 01 01 8b 0e 88 1c 11 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}