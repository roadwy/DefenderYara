
rule Trojan_Win32_Stealerc_AMBH_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.AMBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 ec 31 45 fc 33 55 fc 89 55 ec 8b 45 ec 83 45 f4 64 29 45 f4 83 6d f4 64 83 3d ?? ?? ?? ?? 0c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Stealerc_AMBH_MTB_2{
	meta:
		description = "Trojan:Win32/Stealerc.AMBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d f4 8b 45 ec 31 45 fc d3 ee 03 75 d8 81 3d ?? ?? ?? ?? 03 0b 00 00 } //2
		$a_01_1 = {4c 65 77 69 70 61 64 6f 6d 75 6e 69 66 75 63 20 68 69 68 6f 6b 65 79 69 6c 6f 20 66 65 78 } //2 Lewipadomunifuc hihokeyilo fex
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_Win32_Stealerc_AMBH_MTB_3{
	meta:
		description = "Trojan:Win32/Stealerc.AMBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 74 24 1c 8b 44 24 2c 01 44 24 1c 8b 44 24 10 33 44 24 1c 89 44 24 1c 8b 54 24 1c 89 54 24 1c 8b 44 24 1c 29 44 24 14 8b 4c 24 14 8b c1 c1 e0 04 03 44 24 30 81 3d ?? ?? ?? ?? be 01 00 00 } //1
		$a_03_1 = {8b 44 24 28 01 44 24 18 8b 44 24 10 33 44 24 18 89 44 24 18 8b 54 24 18 89 54 24 18 8b 44 24 18 29 44 24 14 8b 4c 24 14 8b c1 c1 e0 04 03 44 24 2c 81 3d ?? ?? ?? ?? be 01 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}