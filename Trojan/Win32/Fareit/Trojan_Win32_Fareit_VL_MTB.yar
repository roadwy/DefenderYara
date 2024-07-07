
rule Trojan_Win32_Fareit_VL_MTB{
	meta:
		description = "Trojan:Win32/Fareit.VL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {51 59 8b 04 0f 66 3d 90 01 02 e8 90 01 04 52 5a 89 04 0f 66 81 f9 90 01 02 66 83 e9 90 01 01 66 3d 90 01 02 81 f9 90 01 04 75 90 00 } //1
		$a_02_1 = {31 f0 66 81 fa 90 01 02 c3 90 09 04 00 66 3d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Fareit_VL_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.VL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 04 0f 66 81 f9 90 01 02 e8 90 01 04 50 58 89 04 0f 81 fd 90 01 04 66 83 e9 90 01 01 81 fc 90 01 04 81 f9 90 01 04 75 90 09 03 00 80 fe 90 00 } //1
		$a_02_1 = {50 58 31 f0 66 81 fb 90 01 02 c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Fareit_VL_MTB_3{
	meta:
		description = "Trojan:Win32/Fareit.VL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 04 0f 53 5b e8 90 01 04 80 fd 90 01 01 89 04 0f 66 3d 90 01 02 66 83 e9 90 01 01 66 3d 90 01 02 81 f9 90 01 04 75 90 09 03 00 80 fc 90 00 } //1
		$a_02_1 = {31 f0 66 3d 90 01 02 c3 90 09 04 00 66 3d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Fareit_VL_MTB_4{
	meta:
		description = "Trojan:Win32/Fareit.VL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {89 4c 24 04 c1 64 24 04 90 01 01 8b 44 24 0c 01 44 24 04 89 0c 24 c1 2c 24 90 01 01 8b 44 24 14 01 04 24 8b 44 24 10 03 c1 33 04 24 33 44 24 04 83 c4 90 01 01 c3 90 00 } //1
		$a_02_1 = {8b 44 24 24 89 78 04 90 01 03 89 18 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Fareit_VL_MTB_5{
	meta:
		description = "Trojan:Win32/Fareit.VL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b 14 0f 66 f7 c3 90 01 02 31 f2 f7 c7 90 01 04 09 14 08 66 f7 c2 90 01 02 85 c9 75 90 09 09 00 83 e9 90 01 01 f7 c4 90 00 } //2
		$a_02_1 = {8b 14 0f 66 f7 c2 90 01 02 31 f2 66 f7 c2 90 01 02 09 14 08 f6 c1 90 01 01 85 c9 75 90 09 09 00 83 e9 90 01 01 f7 c4 90 00 } //2
		$a_02_2 = {8b 14 0f a8 90 01 01 31 f2 f6 c1 90 01 01 09 14 08 f6 c2 90 01 01 85 c9 75 90 09 06 00 83 e9 90 01 01 f6 c7 90 00 } //2
		$a_02_3 = {8b 14 0f eb 90 01 09 31 f2 81 fe 90 01 04 09 14 08 eb 90 01 09 85 c9 75 90 09 09 00 83 e9 90 01 01 81 fe 90 00 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_02_2  & 1)*2+(#a_02_3  & 1)*2) >=2
 
}