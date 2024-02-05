
rule Trojan_Win32_Raccrypt_GO_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {9f 99 a2 25 c7 85 90 01 04 e9 a9 1a 16 c7 85 90 01 04 eb 24 54 26 c7 85 90 01 04 15 4f 12 30 c7 85 90 01 04 35 2a da 14 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GO_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 65 58 6a 32 66 a3 90 01 04 58 6a 33 66 a3 90 01 04 58 6a 65 66 a3 90 01 04 58 6a 64 66 a3 90 01 04 58 6a 6e 66 a3 90 01 04 58 6a 6c 66 a3 90 01 04 58 6a 6b 66 a3 90 01 04 33 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GO_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {b4 02 d7 cb 90 02 06 c7 05 90 01 04 ff ff ff ff 89 90 02 03 e8 90 01 04 8b ca e8 90 01 04 8b 90 02 03 29 90 02 03 8d 90 02 03 e8 90 02 0f 0f 85 90 0a 5a 00 8b 90 02 03 8b 90 01 01 c1 90 02 08 c7 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GO_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {3b 2d 0b 00 8b 0d 90 01 04 88 04 90 01 01 75 90 00 } //01 00 
		$a_02_1 = {25 bb 52 c0 5d 8b 90 02 02 8b 90 02 04 c1 90 01 01 05 03 90 02 04 c1 90 02 01 04 03 90 02 06 33 90 01 01 33 90 00 } //01 00 
		$a_02_2 = {25 bb 52 c0 5d 8b 90 02 02 8b 90 02 04 c1 90 01 01 04 03 90 02 06 33 90 02 08 c1 90 02 01 05 03 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GO_MTB_5{
	meta:
		description = "Trojan:Win32/Raccrypt.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {bb 9b c6 a0 04 8b 90 02 14 c1 90 01 01 04 03 90 02 1e c1 90 01 01 05 03 90 02 0f 33 90 02 04 33 90 00 } //01 00 
		$a_02_1 = {bb 9b c6 a0 04 8b 90 02 14 c1 90 01 01 05 03 90 02 1e c1 90 01 01 04 03 90 02 0f 33 90 02 04 33 90 00 } //01 00 
		$a_02_2 = {bb 9b c6 a0 04 8b 90 02 14 c1 90 01 01 05 89 90 02 1e c1 90 01 01 04 03 90 02 0f 33 90 02 04 33 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GO_MTB_6{
	meta:
		description = "Trojan:Win32/Raccrypt.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {19 36 6b ff 90 0a 32 00 c1 90 01 01 04 03 90 02 28 c1 90 01 01 05 90 02 0f c7 05 90 02 14 90 17 02 01 01 31 33 90 00 } //01 00 
		$a_02_1 = {19 36 6b ff 90 0a 32 00 c1 90 01 01 05 03 90 02 28 c1 90 01 01 04 90 02 0f c7 05 90 02 14 90 17 02 01 01 31 33 90 00 } //01 00 
		$a_02_2 = {19 36 6b ff 90 0a 32 00 c1 90 01 01 05 90 02 28 c1 90 01 01 04 03 90 02 0f c7 05 90 02 14 90 17 02 01 01 31 33 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GO_MTB_7{
	meta:
		description = "Trojan:Win32/Raccrypt.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c6 05 cf 90 01 03 32 c6 05 90 01 04 2e c6 05 90 01 04 64 c6 05 90 01 04 6c c6 05 90 01 04 6c 90 02 06 c6 05 90 01 04 6b c6 05 90 01 04 65 c6 05 90 01 04 72 c6 05 90 01 04 6e c6 05 90 01 04 65 c6 05 90 01 04 6c ff 15 90 00 } //01 00 
		$a_02_1 = {33 c6 05 c9 90 01 03 32 c6 05 90 01 04 2e c6 05 90 01 04 64 c6 05 90 01 04 6c c6 05 90 01 04 6c 90 02 06 c6 05 90 01 04 6b c6 05 90 01 04 65 c6 05 90 01 04 72 c6 05 90 01 04 6e c6 05 90 01 04 65 c6 05 90 01 04 6c ff 15 90 00 } //01 00 
		$a_02_2 = {33 c6 05 a9 90 01 03 32 c6 05 90 01 04 2e c6 05 90 01 04 64 c6 05 90 01 04 6c c6 05 90 01 04 6c 90 02 06 c6 05 90 01 04 6b c6 05 90 01 04 65 c6 05 90 01 04 72 c6 05 90 01 04 6e c6 05 90 01 04 65 c6 05 90 01 04 6c ff 15 90 00 } //01 00 
		$a_00_3 = {8b 45 0c 01 45 fc 8b 45 fc 31 45 08 c9 c2 08 00 81 00 e1 34 ef c6 c3 } //01 00 
		$a_00_4 = {8b 45 0c 01 45 fc 8b 45 fc 31 45 08 8b 45 08 c9 c2 08 00 81 00 e1 34 ef c6 c3 } //00 00 
	condition:
		any of ($a_*)
 
}