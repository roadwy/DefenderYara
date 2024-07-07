
rule Trojan_Win32_Raccoon_RJ_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 c2 0c 00 55 8b ec 51 90 02 10 8b 45 0c 90 02 10 01 45 fc 83 6d fc 02 8b 45 08 8b 4d 90 01 01 31 08 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccoon_RJ_MTB_2{
	meta:
		description = "Trojan:Win32/Raccoon.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c2 08 00 81 01 e1 34 ef c6 c3 } //1
		$a_03_1 = {8b c3 d3 e8 c7 05 90 01 04 ee 3d ea f4 03 45 cc 89 45 f8 8b 45 e8 31 45 fc 8b 45 fc 31 45 f8 81 3d 90 01 04 6e 0c 00 00 75 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Raccoon_RJ_MTB_3{
	meta:
		description = "Trojan:Win32/Raccoon.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 00 47 86 c8 61 c3 81 00 e1 34 ef c6 c3 01 08 c3 } //1
		$a_03_1 = {03 c6 89 45 90 01 01 8b c6 d3 e8 03 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 33 45 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Raccoon_RJ_MTB_4{
	meta:
		description = "Trojan:Win32/Raccoon.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 05 c7 05 90 01 04 19 36 6b ff 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 83 65 90 01 01 00 8b c6 c1 e0 90 01 01 03 45 90 01 01 33 45 90 01 01 33 c1 2b f8 8b 45 90 01 01 01 45 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccoon_RJ_MTB_5{
	meta:
		description = "Trojan:Win32/Raccoon.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 75 90 01 01 0f b6 92 90 01 04 33 ca 88 4d 90 01 01 0f b6 45 90 01 01 8b 4d 90 01 01 0f b6 91 90 01 04 03 d0 8b 45 90 01 01 88 90 02 20 2b c8 88 4d 90 02 15 2b ca 8b 55 90 01 01 88 8a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccoon_RJ_MTB_6{
	meta:
		description = "Trojan:Win32/Raccoon.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 00 e1 34 ef c6 c3 01 08 c3 } //1
		$a_03_1 = {36 dd 96 53 81 45 90 01 01 38 dd 96 53 8b 4d 90 01 01 8b c6 d3 e0 90 02 20 8b d6 d3 ea 03 c6 89 45 90 01 01 03 55 90 01 01 8b 45 90 01 01 31 45 90 01 01 31 55 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}