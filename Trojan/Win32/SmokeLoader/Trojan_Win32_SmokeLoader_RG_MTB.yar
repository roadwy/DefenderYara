
rule Trojan_Win32_SmokeLoader_RG_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {12 a9 31 bb be be 19 16 c8 86 c1 7e 41 35 5f 16 17 be d2 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_SmokeLoader_RG_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 dc 01 45 fc 8b 4d f8 8b 45 f4 8b fb d3 ef 03 c3 31 45 fc 03 7d d4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_SmokeLoader_RG_MTB_3{
	meta:
		description = "Trojan:Win32/SmokeLoader.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b f7 d3 ee 8d 04 3b 89 45 e0 c7 05 90 01 04 ee 3d ea f4 03 75 e4 8b 45 e0 31 45 fc 33 75 fc 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_SmokeLoader_RG_MTB_4{
	meta:
		description = "Trojan:Win32/SmokeLoader.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cf c1 e9 05 03 4c 24 90 01 01 8b d7 c1 e2 04 03 54 24 90 01 01 8d 04 2f 33 ca 33 c8 2b d9 8b cb c1 e1 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_SmokeLoader_RG_MTB_5{
	meta:
		description = "Trojan:Win32/SmokeLoader.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e0 04 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 8b 4d 90 01 01 8d 14 03 d3 e8 03 45 90 01 01 33 c2 31 45 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_SmokeLoader_RG_MTB_6{
	meta:
		description = "Trojan:Win32/SmokeLoader.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 85 54 fe ff ff dd 8a 30 3f c7 85 5c fe ff ff 1a a0 a6 15 c7 85 8c fe ff ff cb 2e 4a 32 c7 85 cc fd ff ff 37 5f 18 1f c7 85 d4 fd ff ff 3f 18 79 15 c7 85 14 fe ff ff 42 ac ee 22 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}