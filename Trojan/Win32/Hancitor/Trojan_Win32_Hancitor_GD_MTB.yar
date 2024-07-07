
rule Trojan_Win32_Hancitor_GD_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 11 88 10 8b 45 90 01 01 83 c0 01 89 45 90 01 01 8b 4d 90 01 01 83 c1 01 89 4d 90 01 01 8b 15 90 01 04 83 ea 90 01 01 33 c0 2b 55 90 01 01 1b 45 90 01 01 89 55 90 01 01 eb 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Hancitor_GD_MTB_2{
	meta:
		description = "Trojan:Win32/Hancitor.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 7d 08 81 c2 90 01 04 57 8b 35 90 01 04 b0 ef 2a 05 90 01 04 66 0f b6 c8 66 83 c1 90 01 01 66 89 0d 90 01 04 0f b7 c9 3b f1 72 90 01 01 28 1d 90 01 04 8d 4c 1e 90 01 01 66 89 0d 90 01 04 fe c0 b1 90 01 01 f6 e9 a2 90 01 04 c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Hancitor_GD_MTB_3{
	meta:
		description = "Trojan:Win32/Hancitor.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 00 88 86 90 01 04 83 ef 01 83 c6 01 83 3d 90 01 04 04 75 90 00 } //10
		$a_02_1 = {8b 37 02 c2 00 05 90 01 04 81 fd 90 01 04 a1 90 01 04 90 18 81 c6 90 01 04 89 37 89 35 90 01 04 8b f1 6b f6 90 01 01 8b d8 2b de 03 1d 90 01 04 83 c7 04 03 d3 83 6c 24 90 01 01 01 75 90 00 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Hancitor_GD_MTB_4{
	meta:
		description = "Trojan:Win32/Hancitor.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 06 00 00 "
		
	strings :
		$a_00_0 = {8b 55 f8 03 55 f0 8b 45 fc 03 45 f8 8b 4d f4 8a 14 11 88 10 8b 45 f8 83 c0 01 89 45 f8 eb } //10
		$a_02_1 = {03 f0 8b 45 08 03 30 8b 4d 08 89 31 90 02 12 8b 55 08 8b 90 01 01 2b 90 01 01 8b 55 08 89 90 01 01 5e 8b e5 5d c3 90 00 } //10
		$a_02_2 = {89 08 5f 5d c3 90 0a ff 00 90 17 04 01 01 01 01 31 32 30 33 90 02 c8 c7 05 90 01 04 00 00 00 00 01 05 90 01 04 a1 90 01 04 8b 0d 90 00 } //10
		$a_02_3 = {89 08 5b 5d c3 90 0a ff 00 90 17 04 01 01 01 01 31 32 30 33 90 02 c8 c7 05 90 01 04 00 00 00 00 01 05 90 01 04 a1 90 01 04 8b 0d 90 00 } //10
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10+(#a_02_2  & 1)*10+(#a_02_3  & 1)*10+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=21
 
}