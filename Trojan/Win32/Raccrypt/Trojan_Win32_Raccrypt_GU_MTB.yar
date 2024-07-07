
rule Trojan_Win32_Raccrypt_GU_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {88 04 31 83 3d 90 01 04 33 90 18 46 3b 35 90 00 } //1
		$a_02_1 = {30 04 31 81 bc 24 90 01 04 91 05 00 00 90 18 46 3b b4 24 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Raccrypt_GU_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {25 bb 52 c0 5d 8b 90 02 06 8b 90 02 04 c1 90 01 01 04 03 90 02 1e c1 90 02 01 05 03 90 02 28 8b 45 90 01 01 29 45 90 01 01 81 90 01 01 47 86 c8 61 90 02 05 0f 85 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GU_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {51 6a 40 ff 35 90 0a 82 00 6c c6 05 90 01 04 6c 90 02 06 c6 05 90 01 04 6b c6 05 90 01 04 65 c6 05 90 01 04 72 c6 05 90 01 04 6c c6 05 90 01 04 32 c6 05 90 01 04 2e c6 05 90 01 04 6e c6 05 90 01 04 65 c6 05 90 01 04 64 c6 05 90 01 04 33 ff 15 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GU_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b8 65 00 00 00 66 a3 90 01 04 b8 6c 00 00 00 8b c8 66 89 0d 90 01 04 b9 72 00 00 00 66 89 0d 90 01 04 8b 0d 90 01 04 66 a3 90 01 04 a3 90 01 04 51 b8 6b 00 00 00 6a 00 c7 05 90 01 04 33 00 32 00 c7 05 90 01 04 2e 00 64 00 c7 05 90 01 04 6e 00 65 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GU_MTB_5{
	meta:
		description = "Trojan:Win32/Raccrypt.GU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b c6 d3 e8 8b 4d 90 01 01 c7 05 90 01 08 89 45 90 01 01 8d 45 90 01 01 e8 90 01 04 81 fa 90 01 04 90 18 8b 45 90 01 01 8b 4d 90 01 01 03 c6 33 c8 31 4d 90 01 01 81 3d 90 01 08 75 90 00 } //10
		$a_02_1 = {03 c3 50 8b c3 d3 e0 03 45 90 01 01 e8 90 00 } //2
		$a_00_2 = {66 00 75 00 64 00 6b 00 61 00 67 00 61 00 74 00 61 00 } //2 fudkagata
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*2+(#a_00_2  & 1)*2) >=14
 
}