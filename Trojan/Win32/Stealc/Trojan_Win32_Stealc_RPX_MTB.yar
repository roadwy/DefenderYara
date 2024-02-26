
rule Trojan_Win32_Stealc_RPX_MTB{
	meta:
		description = "Trojan:Win32/Stealc.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {03 55 d8 8b 45 ec 31 45 fc 33 55 fc 89 55 d4 8b 45 d4 83 45 f8 64 29 45 f8 83 6d f8 64 8b 55 f8 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Stealc_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/Stealc.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 f6 8b c3 c1 e0 04 03 44 24 30 8b d3 c1 ea 05 03 54 24 28 8d 0c 2b 33 c1 89 54 24 14 89 44 24 10 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Stealc_RPX_MTB_3{
	meta:
		description = "Trojan:Win32/Stealc.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 dc 01 45 fc 8b 4d f8 8d 04 13 d3 ea 89 45 f4 03 55 d4 8b 45 f4 31 45 fc 31 55 fc 8b 45 fc 29 45 f0 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Stealc_RPX_MTB_4{
	meta:
		description = "Trojan:Win32/Stealc.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {e8 00 00 00 00 58 89 45 f0 81 45 f0 cb 07 00 00 8b 45 08 8b 4d f0 89 48 04 8b 45 f0 83 c0 3d 8b 4d 08 89 41 08 } //00 00 
	condition:
		any of ($a_*)
 
}