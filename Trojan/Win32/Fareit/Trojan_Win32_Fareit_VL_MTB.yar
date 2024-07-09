
rule Trojan_Win32_Fareit_VL_MTB{
	meta:
		description = "Trojan:Win32/Fareit.VL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {51 59 8b 04 0f 66 3d ?? ?? e8 ?? ?? ?? ?? 52 5a 89 04 0f 66 81 f9 ?? ?? 66 83 e9 ?? 66 3d ?? ?? 81 f9 ?? ?? ?? ?? 75 } //1
		$a_02_1 = {31 f0 66 81 fa ?? ?? c3 90 09 04 00 66 3d } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Fareit_VL_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.VL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 04 0f 66 81 f9 ?? ?? e8 ?? ?? ?? ?? 50 58 89 04 0f 81 fd ?? ?? ?? ?? 66 83 e9 ?? 81 fc ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 75 90 09 03 00 80 fe } //1
		$a_02_1 = {50 58 31 f0 66 81 fb ?? ?? c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Fareit_VL_MTB_3{
	meta:
		description = "Trojan:Win32/Fareit.VL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 04 0f 53 5b e8 ?? ?? ?? ?? 80 fd ?? 89 04 0f 66 3d ?? ?? 66 83 e9 ?? 66 3d ?? ?? 81 f9 ?? ?? ?? ?? 75 90 09 03 00 80 fc } //1
		$a_02_1 = {31 f0 66 3d ?? ?? c3 90 09 04 00 66 3d } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Fareit_VL_MTB_4{
	meta:
		description = "Trojan:Win32/Fareit.VL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {89 4c 24 04 c1 64 24 04 ?? 8b 44 24 0c 01 44 24 04 89 0c 24 c1 2c 24 ?? 8b 44 24 14 01 04 24 8b 44 24 10 03 c1 33 04 24 33 44 24 04 83 c4 ?? c3 } //1
		$a_02_1 = {8b 44 24 24 89 78 04 ?? ?? ?? 89 18 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Fareit_VL_MTB_5{
	meta:
		description = "Trojan:Win32/Fareit.VL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b 14 0f 66 f7 c3 ?? ?? 31 f2 f7 c7 ?? ?? ?? ?? 09 14 08 66 f7 c2 ?? ?? 85 c9 75 90 09 09 00 83 e9 ?? f7 c4 } //2
		$a_02_1 = {8b 14 0f 66 f7 c2 ?? ?? 31 f2 66 f7 c2 ?? ?? 09 14 08 f6 c1 ?? 85 c9 75 90 09 09 00 83 e9 ?? f7 c4 } //2
		$a_02_2 = {8b 14 0f a8 ?? 31 f2 f6 c1 ?? 09 14 08 f6 c2 ?? 85 c9 75 90 09 06 00 83 e9 ?? f6 c7 } //2
		$a_02_3 = {8b 14 0f eb ?? ?? ?? ?? ?? ?? ?? ?? ?? 31 f2 81 fe ?? ?? ?? ?? 09 14 08 eb ?? ?? ?? ?? ?? ?? ?? ?? ?? 85 c9 75 90 09 09 00 83 e9 ?? 81 fe } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_02_2  & 1)*2+(#a_02_3  & 1)*2) >=2
 
}