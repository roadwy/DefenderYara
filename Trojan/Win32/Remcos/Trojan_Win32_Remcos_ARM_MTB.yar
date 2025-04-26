
rule Trojan_Win32_Remcos_ARM_MTB{
	meta:
		description = "Trojan:Win32/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 04 8d a0 01 43 00 8b f0 81 e6 ff 00 00 00 c1 e8 08 33 04 b5 a0 05 43 00 41 89 04 8d 9c 05 43 00 3b ca } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Remcos_ARM_MTB_2{
	meta:
		description = "Trojan:Win32/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {86 0e 0a 01 01 b9 6c 01 01 01 67 8a 86 e9 e7 00 00 ba 66 01 01 01 67 8a 8e eb e7 00 00 bb 73 01 01 01 67 8a 96 ed e7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Remcos_ARM_MTB_3{
	meta:
		description = "Trojan:Win32/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d8 03 5d a4 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 d4 31 18 83 45 ec 04 6a 00 e8 ?? ?? ?? ?? 83 c0 04 01 45 d4 8b 45 ec 3b 45 d0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Remcos_ARM_MTB_4{
	meta:
		description = "Trojan:Win32/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0d 54 5f 5f 33 36 34 37 39 35 33 38 31 39 80 03 00 00 02 00 0d 54 5f 5f 33 36 34 37 39 36 32 35 37 30 84 03 00 00 02 00 0d 54 5f 5f 33 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Remcos_ARM_MTB_5{
	meta:
		description = "Trojan:Win32/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 f0 8b 44 24 20 8b d0 03 f7 0b 54 24 24 23 54 24 28 23 44 24 24 0b d0 03 d6 8b 44 24 30 8b 74 24 14 83 c0 20 89 44 24 30 3d 00 01 00 00 8b 44 24 10 89 54 24 2c 89 54 24 34 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Remcos_ARM_MTB_6{
	meta:
		description = "Trojan:Win32/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 07 8b 4f f8 05 ?? ?? ?? ?? 03 4d e8 6a 00 ff 77 fc 50 51 53 ff d6 8b 45 e4 8d 7f 28 8b 4d e0 41 } //1
		$a_03_1 = {03 02 03 f0 c7 45 f8 ?? ?? ?? ?? 8d 45 ec 50 6a 04 8d 45 f8 50 56 ff 75 d4 ff 15 ?? ?? ?? ?? 8b 45 c4 01 45 f8 8d 45 f8 6a 00 6a 04 50 56 ff 75 d4 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}