
rule Trojan_Win32_Hancitor_GB_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 f0 0f b7 c3 83 c0 ?? 89 35 ?? ?? ?? ?? 03 45 ?? 8b fe 03 d0 8b 41 ?? 8b da 05 08 36 04 01 2b de 89 41 ?? 83 eb ?? a3 ?? ?? ?? ?? 83 6d ?? 01 75 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Hancitor_GB_MTB_2{
	meta:
		description = "Trojan:Win32/Hancitor.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b7 4d f8 ba ?? ?? ?? ?? c1 e2 ?? 3b 8a ?? ?? ?? ?? 75 ?? eb ?? 8b 45 f4 8b 0c 85 ?? ?? ?? ?? 03 4d 0c 8b 55 f4 89 0c 95 ?? ?? ?? ?? eb ?? 8b 75 ?? 81 c1 ?? ?? ?? ?? 83 c6 03 03 cb 83 ee 03 81 e9 ?? ?? ?? ?? ff e6 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Hancitor_GB_MTB_3{
	meta:
		description = "Trojan:Win32/Hancitor.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b7 c1 80 eb [0-01] 89 44 24 [0-01] 03 c6 8b 74 24 [0-01] 03 d0 0f b7 c2 02 da 89 44 24 [0-01] 8b 44 24 [0-01] 05 [0-04] 66 89 15 [0-04] 89 06 83 c6 04 83 6c 24 [0-01] 01 a3 [0-04] 8b 44 24 [0-01] 89 74 24 [0-01] 0f b7 f0 0f 85 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Hancitor_GB_MTB_4{
	meta:
		description = "Trojan:Win32/Hancitor.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 00 88 87 ?? ?? ?? ?? 47 39 1d ?? ?? ?? ?? 77 ?? 0f b6 c1 8a cb 02 c9 a3 ?? ?? ?? ?? 8b 44 24 ?? 2a c8 80 c1 ?? 88 0d ?? ?? ?? ?? eb } //10
		$a_02_1 = {2a c2 2c 63 a2 ?? ?? ?? ?? 8b 07 05 ?? ?? ?? ?? 89 07 83 c7 04 a3 ?? ?? ?? ?? 8a c2 02 c0 04 ?? 02 05 ?? ?? ?? ?? 02 c1 83 6c 24 ?? 01 75 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Hancitor_GB_MTB_5{
	meta:
		description = "Trojan:Win32/Hancitor.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_02_0 = {03 f0 8b 45 08 03 30 8b 4d 08 89 31 8b 55 08 8b 02 2d ?? ?? ?? ?? 8b 4d 08 89 01 5e 8b e5 5d c3 } //10
		$a_02_1 = {89 08 5b 5d c3 90 0a ff 00 33 [0-dc] c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d } //10
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=21
 
}