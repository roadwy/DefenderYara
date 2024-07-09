
rule Trojan_Win32_Raccrypt_GC_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {61 9b 21 1a c7 85 ?? ?? ?? ?? e7 d0 87 49 c7 85 ?? ?? ?? ?? 96 3a d0 46 c7 85 ?? ?? ?? ?? 29 5f 9d 30 c7 85 ?? ?? ?? ?? 6b 33 00 4b } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GC_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {51 ba 6c 00 00 00 6a 00 c7 05 ?? ?? ?? ?? 6c 00 33 00 c7 05 ?? ?? ?? ?? 6b 00 65 00 c7 05 ?? ?? ?? ?? 6e 00 65 00 66 89 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? ff 15 90 0a 58 00 2e 00 00 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GC_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 73 58 6a 6d 66 a3 ?? ?? ?? ?? 58 6a 67 66 a3 ?? ?? ?? ?? 58 6a 69 66 a3 ?? ?? ?? ?? 58 6a 6c 66 a3 ?? ?? ?? ?? 58 6a 32 66 a3 ?? ?? ?? ?? 58 6a 6c 8b 3d ?? ?? ?? ?? 66 a3 ?? ?? ?? ?? 58 6a 33 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GC_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 40 ff 35 [0-14] c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 6f c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 56 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 69 ff 15 } //10
		$a_02_1 = {44 00 6b c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 2e c6 05 ?? ?? ?? ?? 64 c6 05 ?? ?? ?? ?? 6c [0-07] c6 05 ?? ?? ?? ?? 6e c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 33 c6 05 ?? ?? ?? ?? 32 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 74 ff 15 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=10
 
}
rule Trojan_Win32_Raccrypt_GC_MTB_5{
	meta:
		description = "Trojan:Win32/Raccrypt.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_02_0 = {3b 2d 0b 00 8b 0d [0-04] 88 04 19 83 3d [0-04] 44 } //1
		$a_80_1 = {72 75 6e 65 78 6f 62 6f 7a 65 7a } //runexobozez  1
		$a_80_2 = {6a 65 6d 65 66 75 6d 6f 72 65 70 6f 76 65 74 61 } //jemefumorepoveta  1
		$a_80_3 = {58 6f 74 61 66 69 62 69 77 61 63 75 79 69 20 6e 75 6c } //Xotafibiwacuyi nul  1
		$a_80_4 = {2e 70 64 62 } //.pdb  1
		$a_80_5 = {43 6f 70 79 72 69 67 68 7a 20 28 43 29 20 32 30 32 31 2c 20 66 75 64 6b 6f 72 74 61 } //Copyrighz (C) 2021, fudkorta  1
		$a_80_6 = {50 75 6c 65 7a 75 66 69 67 65 74 20 67 61 63 75 77 75 6d 75 68 69 20 79 6f 66 65 6c 65 6b 75 64 75 72 69 6b 61 20 64 75 6c 69 6b 61 68 75 79 } //Pulezufiget gacuwumuhi yofelekudurika dulikahuy  1
	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}
rule Trojan_Win32_Raccrypt_GC_MTB_6{
	meta:
		description = "Trojan:Win32/Raccrypt.GC!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {b8 3b 2d 0b 00 01 45 fc 8b 45 fc 8a 04 08 88 04 31 41 3b 0d } //10
		$a_01_1 = {89 30 5e c2 08 00 33 44 24 04 c2 04 00 81 00 ae 36 ef c6 c3 01 08 c3 29 08 c3 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}