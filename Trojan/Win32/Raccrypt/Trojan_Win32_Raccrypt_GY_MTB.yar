
rule Trojan_Win32_Raccrypt_GY_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {25 bb 52 c0 5d 8b 90 02 0a c1 90 01 01 04 03 90 02 19 c1 90 02 01 05 03 90 02 0a 90 17 02 01 01 31 33 90 02 14 0f 85 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GY_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8f fb 24 5e c7 85 90 01 04 76 96 cc 13 c7 85 90 01 04 68 e3 5c 14 c7 85 90 01 04 aa e4 a4 53 c7 85 90 01 04 cc 54 04 18 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GY_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {23 29 9b 47 c7 85 90 01 04 06 80 e6 6a c7 85 90 01 04 07 b5 1f 11 c7 85 90 01 04 c8 cc 51 4b c7 85 90 01 04 82 1b a6 1f c7 85 90 01 04 c9 ba ac 1b c7 85 90 01 04 d6 f7 22 3f 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GY_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {21 e8 46 32 c7 85 90 01 04 25 bd b1 77 c7 85 90 01 04 d3 29 2d 6c c7 85 90 01 04 a2 b9 cd 19 c7 85 90 01 04 fb d0 9d 68 c7 85 90 01 04 dc c0 69 54 c7 85 90 01 04 98 c3 e4 01 c7 85 90 01 04 be 14 4a 0a 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GY_MTB_5{
	meta:
		description = "Trojan:Win32/Raccrypt.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec b8 90 0a 6e 00 c6 05 90 01 04 50 c6 05 90 01 04 61 c6 05 90 01 04 65 c6 05 90 01 04 6c c6 05 90 01 04 69 c6 05 90 01 04 75 c6 05 90 01 04 63 c6 05 90 01 04 74 c6 05 90 01 04 74 c6 05 90 01 04 72 c6 05 90 01 04 72 c3 c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GY_MTB_6{
	meta:
		description = "Trojan:Win32/Raccrypt.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {58 6a 72 66 a3 90 01 04 58 6a 6c 66 a3 90 01 04 58 6a 32 66 a3 90 01 04 58 6a 2e 66 a3 90 01 04 58 6a 6e 66 a3 90 01 04 58 6a 65 66 a3 90 01 04 58 6a 64 66 a3 90 01 04 58 6a 33 66 a3 90 01 04 58 6a 65 66 a3 90 01 04 58 68 90 01 04 66 a3 90 01 04 ff 15 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GY_MTB_7{
	meta:
		description = "Trojan:Win32/Raccrypt.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {c7 45 f8 40 00 00 00 90 02 07 c6 05 90 01 04 65 c6 05 90 01 04 50 c6 05 90 01 04 00 c6 05 90 01 05 c6 05 90 01 04 63 c6 05 90 01 04 61 c6 05 90 01 04 74 c6 05 90 01 04 72 90 00 } //10
		$a_00_1 = {6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 } //1 kernel32.dll
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1) >=11
 
}
rule Trojan_Win32_Raccrypt_GY_MTB_8{
	meta:
		description = "Trojan:Win32/Raccrypt.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 00 c7 05 90 01 04 64 00 6c 00 c7 05 90 01 04 72 00 6e 00 c7 05 90 01 04 6b 00 65 00 c7 05 90 01 04 33 00 32 00 c7 05 90 01 04 6c 00 00 00 90 00 } //1
		$a_02_1 = {74 00 c7 05 90 01 04 56 69 72 74 c7 05 90 01 04 75 61 6c 50 c7 05 90 01 04 72 6f 74 65 c6 05 90 01 04 63 ff 15 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GY_MTB_9{
	meta:
		description = "Trojan:Win32/Raccrypt.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_02_0 = {6c 66 c7 05 90 01 04 65 63 c6 05 90 01 04 74 66 c7 05 90 01 04 72 74 c6 05 90 01 04 75 c6 05 90 01 04 69 ff 15 90 00 } //10
		$a_02_1 = {f6 56 ff 35 90 01 04 c6 05 90 01 04 6c c6 05 90 01 04 74 c6 05 90 01 04 65 c6 05 90 01 04 63 c6 05 90 01 04 74 c6 05 90 01 04 72 c6 05 90 01 04 75 c6 05 90 01 04 69 ff 15 90 00 } //10
		$a_02_2 = {81 ec 2c 05 00 00 56 c6 05 90 01 04 6b c6 05 90 01 04 65 c6 05 90 01 04 72 c6 05 90 01 04 2e c6 05 90 01 04 64 c6 05 90 01 04 6c c6 05 90 01 04 00 90 00 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_02_2  & 1)*10) >=10
 
}