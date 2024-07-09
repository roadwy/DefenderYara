
rule Trojan_Win32_Raccoon_M_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c1 e0 04 89 01 c3 [0-04] 33 44 24 04 c2 04 00 81 00 cc 36 ef c6 c3 [0-04] 01 08 c3 } //1
		$a_03_1 = {33 f6 81 3d ?? ?? ?? ?? 34 01 00 00 } //1
		$a_00_2 = {8a 94 01 3b 2d 0b 00 88 14 30 40 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Raccoon_M_MTB_2{
	meta:
		description = "Trojan:Win32/Raccoon.M!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 44 24 24 50 6a 00 ff d6 6a 00 8d 4c 24 64 51 ff d7 8d 54 24 48 52 ff d3 33 c9 33 c0 8d 54 24 1c 52 66 89 44 24 24 66 89 4c 24 26 8b 44 24 24 50 51 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Raccoon_M_MTB_3{
	meta:
		description = "Trojan:Win32/Raccoon.M!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {51 c7 04 24 02 00 00 00 8b 44 24 0c 01 04 24 83 2c 24 02 8b 44 24 08 8b 0c 24 31 08 59 c2 08 00 8b 4c 24 04 8b 01 89 44 24 04 8b 44 24 08 90 01 44 24 04 8b 54 24 04 89 11 c2 08 00 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}