
rule Trojan_Win32_Raccoon_DE_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_81_0 = {6d 69 72 65 6c 61 } //3 mirela
		$a_81_1 = {46 69 6c 75 64 75 6a 6f 76 61 76 61 } //3 Filudujovava
		$a_81_2 = {43 6f 70 79 46 69 6c 65 57 } //3 CopyFileW
		$a_81_3 = {53 79 73 74 65 6d 54 69 6d 65 54 6f 54 7a 53 70 65 63 69 66 69 63 4c 6f 63 61 6c 54 69 6d 65 } //3 SystemTimeToTzSpecificLocalTime
		$a_81_4 = {52 65 6c 65 61 73 65 4d 75 74 65 78 } //3 ReleaseMutex
		$a_81_5 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 41 } //3 OutputDebugStringA
		$a_81_6 = {4d 6f 76 65 46 69 6c 65 41 } //3 MoveFileA
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}
rule Trojan_Win32_Raccoon_DE_MTB_2{
	meta:
		description = "Trojan:Win32/Raccoon.DE!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b f1 8b ce c1 e1 04 03 4d e8 8b c6 c1 e8 05 03 45 ec 03 fe 33 cf 33 c8 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Raccoon_DE_MTB_3{
	meta:
		description = "Trojan:Win32/Raccoon.DE!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e1 04 03 4d dc 89 4d fc 8d 0c 03 c1 e8 05 03 45 d8 89 4d ec 89 45 f8 8b 45 ec 31 45 fc } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Raccoon_DE_MTB_4{
	meta:
		description = "Trojan:Win32/Raccoon.DE!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 44 24 04 c2 04 00 81 00 dc 35 ef c6 c3 } //10
		$a_01_1 = {8b 4d f4 8b df d3 eb 03 5d dc 33 c3 89 45 ec 83 fa 27 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}