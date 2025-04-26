
rule Trojan_Win32_Raccrypt_GB_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {b8 3b 2d 0b 00 01 45 ?? 8b 45 ?? 8a 04 08 88 04 31 41 3b 0d } //10
		$a_00_1 = {c1 e0 04 89 01 c3 31 08 c3 33 44 24 04 c2 04 00 81 00 fe 36 ef c6 c3 01 08 c3 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Raccrypt_GB_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {b8 3b 2d 0b 00 01 45 fc 8b 45 fc 8a 04 08 88 04 31 41 3b 0d } //10
		$a_02_1 = {c1 e0 04 89 01 c3 83 3d ?? ?? ?? ?? 7e 90 18 8b 44 24 04 31 06 c2 04 00 33 44 24 04 c2 04 00 81 00 ae 36 ef c6 c3 01 08 c3 29 08 c3 } //10
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Raccrypt_GB_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {25 bb 52 c0 5d 8b [0-0a] c1 ?? 04 03 [0-1e] c1 [0-01] 05 03 90 0a 0f 00 90 17 02 01 01 31 33 [0-32] 0f 85 } //1
		$a_00_1 = {89 75 fc 8b 45 10 89 45 fc 8b 45 0c 31 45 fc 8b 45 fc 8b 4d 08 89 01 5e c9 c2 0c 00 81 00 a4 36 ef c6 c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GB_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {19 36 6b ff 90 0a 5a 00 90 17 02 01 01 31 33 [0-2d] c1 ?? 04 03 [0-28] c1 ?? 05 [0-0f] c7 05 } //1
		$a_02_1 = {19 36 6b ff 90 0a 5a 00 90 17 02 01 01 31 33 [0-2d] c1 ?? 05 03 [0-28] c1 ?? 04 [0-0f] c7 05 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GB_MTB_5{
	meta:
		description = "Trojan:Win32/Raccrypt.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {19 36 6b ff 90 0a 32 00 c1 ?? 04 03 [0-28] 90 17 02 01 01 31 33 [0-14] c1 ?? 05 03 [0-0f] [0-14] c7 05 } //1
		$a_02_1 = {19 36 6b ff 90 0a 32 00 c1 ?? 05 03 [0-28] 90 17 02 01 01 31 33 [0-14] c1 ?? 04 03 [0-0f] [0-14] c7 05 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GB_MTB_6{
	meta:
		description = "Trojan:Win32/Raccrypt.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {50 72 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 6c 66 c7 05 ?? ?? ?? ?? ?? ?? ff 15 90 0a 78 00 cc cc 51 68 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 60 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 6f ff 15 } //10
		$a_00_1 = {6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 } //1 kernel32.dll
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1) >=11
 
}
rule Trojan_Win32_Raccrypt_GB_MTB_7{
	meta:
		description = "Trojan:Win32/Raccrypt.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {25 bb 52 c0 5d 8b [0-0a] c1 ?? 04 03 [0-1e] c1 ?? 05 03 [0-0f] 90 17 02 01 01 31 33 [0-32] 0f 85 } //1
		$a_02_1 = {25 bb 52 c0 5d 83 [0-0a] c1 ?? 04 03 [0-1e] c1 ?? 05 03 [0-0f] 90 17 02 01 01 31 33 [0-32] 0f 85 } //1
		$a_02_2 = {25 bb 52 c0 5d 8b [0-0a] c1 ?? 05 89 [0-1e] c1 ?? 04 03 [0-0f] 90 17 02 01 01 31 33 [0-32] 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GB_MTB_8{
	meta:
		description = "Trojan:Win32/Raccrypt.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {25 bb 52 c0 5d 8b [0-0a] c1 ?? 04 03 [0-1e] c1 ?? 05 03 [0-0f] 90 17 02 01 01 31 33 ?? 90 17 02 01 01 31 33 } //1
		$a_02_1 = {25 bb 52 c0 5d 8b [0-14] c1 ?? 05 89 [0-1e] c1 ?? 04 03 [0-0f] 90 17 02 01 01 31 33 [0-02] 90 17 02 01 01 31 33 } //1
		$a_02_2 = {25 bb 52 c0 5d 8b [0-14] c1 ?? 04 03 [0-1e] c1 ?? 05 89 [0-1e] 90 17 02 01 01 31 33 [0-0f] 90 17 02 01 01 31 33 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GB_MTB_9{
	meta:
		description = "Trojan:Win32/Raccrypt.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {b8 3b 2d 0b 00 01 05 ?? ?? ?? ?? 6a 65 58 6a 32 66 a3 ?? ?? ?? ?? 58 6a 2e 66 a3 ?? ?? ?? ?? 58 6a 6e 66 a3 ?? ?? ?? ?? 58 6a 65 66 a3 ?? ?? ?? ?? 58 6a 64 66 a3 ?? ?? ?? ?? 58 6a 33 } //1
		$a_02_1 = {b8 3b 2d 0b 00 01 05 ?? ?? ?? ?? b8 65 00 00 00 66 a3 ?? ?? ?? ?? b8 33 00 00 00 66 a3 ?? ?? ?? ?? b9 6b 00 00 00 ba 72 00 00 00 b8 6c 00 00 00 68 ?? ?? ?? ?? c7 05 [0-08] c7 05 [0-08] c7 05 [0-08] c7 05 ?? ?? ?? ?? 6c 00 00 00 66 89 0d ?? ?? ?? ?? 66 89 15 ?? ?? ?? ?? 66 a3 ?? ?? ?? ?? ff 15 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}