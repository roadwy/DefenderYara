
rule Trojan_Win32_Amadey_RPX_MTB{
	meta:
		description = "Trojan:Win32/Amadey.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 da cc 00 00 00 81 da aa 00 00 00 c1 c2 b2 83 c3 6e c1 c7 ee f7 d3 c1 df 2d 8b 7d 08 f6 17 80 07 9f fe 07 47 e2 f6 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Amadey_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/Amadey.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c4 30 33 c0 5e c2 04 00 56 8b 35 90 01 04 6a 00 6a 00 6a 00 68 90 01 04 6a 00 6a 00 ff d6 6a 00 6a 00 6a 00 68 90 01 04 6a 00 6a 00 ff d6 8b 35 90 01 04 90 90 68 30 75 00 00 ff d6 eb f7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Amadey_RPX_MTB_3{
	meta:
		description = "Trojan:Win32/Amadey.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 45 fc 06 8d 95 d0 fc ff ff 83 bd e4 fc ff ff 08 8d bd d0 fc ff ff 8b 85 e0 fc ff ff 8d 8d b0 fc ff ff 0f 43 95 d0 fc ff ff 0f 43 bd d0 fc ff ff c7 85 c0 fc ff ff 00 00 00 00 c7 85 c4 fc ff ff 0f 00 00 00 8d 1c 42 c6 85 b0 fc ff ff 00 } //00 00 
	condition:
		any of ($a_*)
 
}