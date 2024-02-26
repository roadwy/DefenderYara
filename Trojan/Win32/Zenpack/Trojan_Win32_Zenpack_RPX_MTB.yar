
rule Trojan_Win32_Zenpack_RPX_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 85 e4 fe ff ff ff d1 83 ec 04 8b 8d e4 fe ff ff 81 c1 01 00 00 00 89 e2 89 02 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zenpack_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpack.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 d0 8b 4d d4 8b 55 d8 be 00 01 00 00 81 c1 01 00 00 00 89 45 cc 89 c8 89 55 c8 99 f7 fe } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zenpack_RPX_MTB_3{
	meta:
		description = "Trojan:Win32/Zenpack.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 c2 eb 1b 89 f8 50 8f 05 90 01 04 40 42 01 c2 31 35 90 01 04 8d 05 90 01 04 ff e0 40 89 d8 50 8f 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zenpack_RPX_MTB_4{
	meta:
		description = "Trojan:Win32/Zenpack.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 f6 8d 9b 00 00 00 00 83 3d 90 01 03 00 0b 75 0e 8d 8c 24 2c 01 00 00 51 6a 00 6a 00 ff d7 81 fe 4c 13 00 00 0f 85 19 0b 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zenpack_RPX_MTB_5{
	meta:
		description = "Trojan:Win32/Zenpack.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 85 80 fc ff ff ff d1 83 ec 0c 8b 8d cc fc ff ff 66 81 39 45 00 0f 94 c3 8b 95 bc fc ff ff 66 81 3a 4c 00 0f 94 c7 20 fb 8b b5 b8 fc ff ff } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zenpack_RPX_MTB_6{
	meta:
		description = "Trojan:Win32/Zenpack.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 c0 80 bd 06 ff ff ff 2e 0f 94 c1 8b 95 ec fe ff ff 80 3a 54 0f 94 c5 20 e9 f6 c1 01 89 85 f0 fe ff ff } //01 00 
		$a_01_1 = {8d 85 fc fe ff ff 05 04 00 00 00 89 85 e8 fe ff ff 8b 85 e8 fe ff ff 80 38 45 } //00 00 
	condition:
		any of ($a_*)
 
}