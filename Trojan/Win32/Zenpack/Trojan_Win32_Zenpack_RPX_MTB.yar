
rule Trojan_Win32_Zenpack_RPX_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 85 e4 fe ff ff ff d1 83 ec 04 8b 8d e4 fe ff ff 81 c1 01 00 00 00 89 e2 89 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpack_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpack.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 d0 8b 4d d4 8b 55 d8 be 00 01 00 00 81 c1 01 00 00 00 89 45 cc 89 c8 89 55 c8 99 f7 fe } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpack_RPX_MTB_3{
	meta:
		description = "Trojan:Win32/Zenpack.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 4d a8 8b 4d ac 89 48 0c 89 58 04 8b 4d a8 89 08 c7 40 08 04 00 00 00 89 7d a4 89 55 a0 89 75 9c ff d2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpack_RPX_MTB_4{
	meta:
		description = "Trojan:Win32/Zenpack.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c2 eb 1b 89 f8 50 8f 05 ?? ?? ?? ?? 40 42 01 c2 31 35 ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? ff e0 40 89 d8 50 8f 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpack_RPX_MTB_5{
	meta:
		description = "Trojan:Win32/Zenpack.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 f6 8d 9b 00 00 00 00 83 3d ?? ?? ?? 00 0b 75 0e 8d 8c 24 2c 01 00 00 51 6a 00 6a 00 ff d7 81 fe 4c 13 00 00 0f 85 19 0b 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpack_RPX_MTB_6{
	meta:
		description = "Trojan:Win32/Zenpack.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 85 80 fc ff ff ff d1 83 ec 0c 8b 8d cc fc ff ff 66 81 39 45 00 0f 94 c3 8b 95 bc fc ff ff 66 81 3a 4c 00 0f 94 c7 20 fb 8b b5 b8 fc ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpack_RPX_MTB_7{
	meta:
		description = "Trojan:Win32/Zenpack.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 5e a8 66 32 f7 64 24 1c 8b 44 24 1c 81 6c 24 0c 00 02 32 55 81 44 24 34 9f 12 a5 12 b8 bf 91 2a 1d f7 64 24 10 8b 44 24 10 81 6c 24 3c fa 7a 76 1f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpack_RPX_MTB_8{
	meta:
		description = "Trojan:Win32/Zenpack.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 c0 80 bd 06 ff ff ff 2e 0f 94 c1 8b 95 ec fe ff ff 80 3a 54 0f 94 c5 20 e9 f6 c1 01 89 85 f0 fe ff ff } //1
		$a_01_1 = {8d 85 fc fe ff ff 05 04 00 00 00 89 85 e8 fe ff ff 8b 85 e8 fe ff ff 80 38 45 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}