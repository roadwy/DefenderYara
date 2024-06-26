
rule Trojan_Win32_Raccrypt_GB_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {b8 3b 2d 0b 00 01 45 90 01 01 8b 45 90 01 01 8a 04 08 88 04 31 41 3b 0d 90 00 } //0a 00 
		$a_00_1 = {c1 e0 04 89 01 c3 31 08 c3 33 44 24 04 c2 04 00 81 00 fe 36 ef c6 c3 01 08 c3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GB_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_00_0 = {b8 3b 2d 0b 00 01 45 fc 8b 45 fc 8a 04 08 88 04 31 41 3b 0d } //0a 00 
		$a_02_1 = {c1 e0 04 89 01 c3 83 3d 90 01 04 7e 90 18 8b 44 24 04 31 06 c2 04 00 33 44 24 04 c2 04 00 81 00 ae 36 ef c6 c3 01 08 c3 29 08 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GB_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {25 bb 52 c0 5d 8b 90 02 0a c1 90 01 01 04 03 90 02 1e c1 90 02 01 05 03 90 0a 0f 00 90 17 02 01 01 31 33 90 02 32 0f 85 90 00 } //01 00 
		$a_00_1 = {89 75 fc 8b 45 10 89 45 fc 8b 45 0c 31 45 fc 8b 45 fc 8b 4d 08 89 01 5e c9 c2 0c 00 81 00 a4 36 ef c6 c3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GB_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {19 36 6b ff 90 0a 5a 00 90 17 02 01 01 31 33 90 02 2d c1 90 01 01 04 03 90 02 28 c1 90 01 01 05 90 02 0f c7 05 90 00 } //01 00 
		$a_02_1 = {19 36 6b ff 90 0a 5a 00 90 17 02 01 01 31 33 90 02 2d c1 90 01 01 05 03 90 02 28 c1 90 01 01 04 90 02 0f c7 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GB_MTB_5{
	meta:
		description = "Trojan:Win32/Raccrypt.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {19 36 6b ff 90 0a 32 00 c1 90 01 01 04 03 90 02 28 90 17 02 01 01 31 33 90 02 14 c1 90 01 01 05 03 90 02 0f 90 02 14 c7 05 90 00 } //01 00 
		$a_02_1 = {19 36 6b ff 90 0a 32 00 c1 90 01 01 05 03 90 02 28 90 17 02 01 01 31 33 90 02 14 c1 90 01 01 04 03 90 02 0f 90 02 14 c7 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GB_MTB_6{
	meta:
		description = "Trojan:Win32/Raccrypt.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {50 72 c6 05 90 01 04 74 c6 05 90 01 04 75 c6 05 90 01 04 6c 66 c7 05 90 01 06 ff 15 90 0a 78 00 cc cc 51 68 90 01 04 c6 05 90 01 04 61 c6 05 90 01 04 74 c6 05 90 01 04 60 c7 05 90 01 08 c6 05 90 01 04 6f ff 15 90 00 } //01 00 
		$a_00_1 = {6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 } //00 00  kernel32.dll
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GB_MTB_7{
	meta:
		description = "Trojan:Win32/Raccrypt.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {25 bb 52 c0 5d 8b 90 02 0a c1 90 01 01 04 03 90 02 1e c1 90 01 01 05 03 90 02 0f 90 17 02 01 01 31 33 90 02 32 0f 85 90 00 } //01 00 
		$a_02_1 = {25 bb 52 c0 5d 83 90 02 0a c1 90 01 01 04 03 90 02 1e c1 90 01 01 05 03 90 02 0f 90 17 02 01 01 31 33 90 02 32 0f 85 90 00 } //01 00 
		$a_02_2 = {25 bb 52 c0 5d 8b 90 02 0a c1 90 01 01 05 89 90 02 1e c1 90 01 01 04 03 90 02 0f 90 17 02 01 01 31 33 90 02 32 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GB_MTB_8{
	meta:
		description = "Trojan:Win32/Raccrypt.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {25 bb 52 c0 5d 8b 90 02 0a c1 90 01 01 04 03 90 02 1e c1 90 01 01 05 03 90 02 0f 90 17 02 01 01 31 33 90 01 01 90 17 02 01 01 31 33 90 00 } //01 00 
		$a_02_1 = {25 bb 52 c0 5d 8b 90 02 14 c1 90 01 01 05 89 90 02 1e c1 90 01 01 04 03 90 02 0f 90 17 02 01 01 31 33 90 02 02 90 17 02 01 01 31 33 90 00 } //01 00 
		$a_02_2 = {25 bb 52 c0 5d 8b 90 02 14 c1 90 01 01 04 03 90 02 1e c1 90 01 01 05 89 90 02 1e 90 17 02 01 01 31 33 90 02 0f 90 17 02 01 01 31 33 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GB_MTB_9{
	meta:
		description = "Trojan:Win32/Raccrypt.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {b8 3b 2d 0b 00 01 05 90 01 04 6a 65 58 6a 32 66 a3 90 01 04 58 6a 2e 66 a3 90 01 04 58 6a 6e 66 a3 90 01 04 58 6a 65 66 a3 90 01 04 58 6a 64 66 a3 90 01 04 58 6a 33 90 00 } //01 00 
		$a_02_1 = {b8 3b 2d 0b 00 01 05 90 01 04 b8 65 00 00 00 66 a3 90 01 04 b8 33 00 00 00 66 a3 90 01 04 b9 6b 00 00 00 ba 72 00 00 00 b8 6c 00 00 00 68 90 01 04 c7 05 90 02 08 c7 05 90 02 08 c7 05 90 02 08 c7 05 90 01 04 6c 00 00 00 66 89 0d 90 01 04 66 89 15 90 01 04 66 a3 90 01 04 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}