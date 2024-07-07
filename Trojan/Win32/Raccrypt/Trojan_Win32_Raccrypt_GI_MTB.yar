
rule Trojan_Win32_Raccrypt_GI_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {77 35 a0 44 c7 44 24 90 01 01 93 35 23 2d c7 44 24 90 01 01 99 da f3 4c c7 44 24 90 01 01 c3 f1 76 08 c7 44 24 90 01 01 d9 ba db 67 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GI_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {25 bb 52 c0 5d 8b 90 02 14 c1 90 01 01 05 89 90 02 1e c1 90 01 01 04 03 90 02 0f 33 90 00 } //1
		$a_00_1 = {33 44 24 04 c2 04 00 81 00 f9 34 ef c6 c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GI_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b4 02 d7 cb c7 05 90 01 04 ff ff ff ff 89 90 01 01 24 90 01 01 e8 90 02 0d e8 90 01 04 2b 74 24 90 01 01 8d 44 24 90 01 01 89 74 24 90 01 01 e8 90 02 08 0f 85 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GI_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {50 b9 72 00 00 00 ba 6c 00 00 00 6a 00 c7 05 90 01 04 64 00 6c 00 c7 05 90 01 04 6c 00 00 00 66 89 0d 90 01 04 66 89 15 90 01 04 ff 15 90 0a 6b 00 ba 65 00 00 00 90 02 04 b8 6b 00 00 00 90 02 14 ba 2e 00 00 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GI_MTB_5{
	meta:
		description = "Trojan:Win32/Raccrypt.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {8a 94 31 36 23 01 00 88 14 30 81 c4 90 01 04 c3 90 00 } //1
		$a_00_1 = {51 c7 04 24 02 00 00 00 8b 44 24 08 01 04 24 83 2c 24 02 8b 04 24 31 01 59 c2 } //1
		$a_02_2 = {b4 02 d7 cb c7 05 90 01 04 ff ff ff ff 90 0a 10 00 c7 05 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Raccrypt_GI_MTB_6{
	meta:
		description = "Trojan:Win32/Raccrypt.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {32 2e 64 6c c7 05 90 01 04 6b 65 72 6e 66 c7 05 90 01 04 65 6c c6 05 90 01 04 33 66 c7 05 90 01 04 6c 00 ff 15 90 00 } //1
		$a_02_1 = {b1 74 50 a3 90 01 0b 61 6c 66 c7 05 90 01 04 72 6f c6 05 90 01 04 50 c7 05 90 01 08 88 0d 90 01 04 c6 05 90 01 04 75 c7 05 90 01 04 56 69 72 74 ff 15 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Raccrypt_GI_MTB_7{
	meta:
		description = "Trojan:Win32/Raccrypt.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {32 2e 64 6c c7 05 90 01 04 6b 65 72 6e 66 c7 05 90 01 04 65 6c c6 05 90 01 04 33 66 c7 05 90 01 04 6c 00 ff 15 90 00 } //1
		$a_02_1 = {b1 74 50 a3 90 02 04 66 c7 05 90 02 06 66 c7 05 90 02 06 c6 05 90 01 04 50 c7 05 90 01 08 88 0d 90 01 04 c6 05 90 01 04 75 c7 05 90 01 04 56 69 72 74 ff 15 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}