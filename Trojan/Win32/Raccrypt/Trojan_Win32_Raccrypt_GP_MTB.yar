
rule Trojan_Win32_Raccrypt_GP_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {b8 3b 2d 0b 00 01 45 74 8b 45 74 8a 04 08 88 04 31 41 3b 0d 90 01 04 0f 82 90 00 } //01 00 
		$a_02_1 = {33 44 24 04 c2 90 01 01 00 81 00 dc 35 ef c6 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GP_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 44 24 90 01 01 8b 44 24 90 01 01 8b 4c 24 90 01 01 33 44 24 90 01 01 03 4c 24 90 01 01 c7 05 90 01 04 ee 3d ea f4 90 17 02 01 01 31 33 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GP_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {3b 2d 0b 00 8b 0d 90 01 04 88 04 31 75 90 00 } //01 00 
		$a_02_1 = {25 bb 52 c0 5d 8b 90 02 02 8b 90 02 04 c1 90 01 01 04 03 90 02 04 c1 90 02 01 05 03 90 02 06 33 90 01 01 33 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GP_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {b8 3b 2d 0b 00 01 45 74 8b 45 74 8a 04 08 88 04 31 41 3b 0d 90 01 04 0f 82 90 00 } //01 00 
		$a_02_1 = {25 bb 52 c0 5d 8b 90 02 02 8b 90 02 04 c1 90 01 01 04 03 90 02 04 c1 90 02 01 05 03 90 02 06 33 90 01 01 33 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GP_MTB_5{
	meta:
		description = "Trojan:Win32/Raccrypt.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {b1 6d b0 6c 88 0d 90 01 04 c6 05 90 01 04 73 a2 90 01 04 c6 05 90 01 04 32 c6 05 90 01 04 69 c6 05 90 01 04 33 c6 05 90 01 04 00 c6 05 90 01 04 67 c6 05 90 01 04 64 88 0d 90 01 04 a2 90 01 04 c6 05 90 01 04 2e c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GP_MTB_6{
	meta:
		description = "Trojan:Win32/Raccrypt.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {b0 65 b1 6c 68 90 02 09 c6 05 90 01 04 72 c6 05 90 01 04 2e c6 05 90 01 04 64 90 02 06 c6 05 90 01 04 00 c6 05 90 01 04 6e 90 02 0c c6 05 90 01 04 33 c6 05 90 01 04 32 90 02 05 c6 05 90 01 04 6b ff 15 90 00 } //01 00 
		$a_02_1 = {b0 74 c6 05 90 01 04 00 c6 05 90 01 04 50 c6 05 90 01 04 61 c6 05 90 01 04 6f 90 02 14 c6 05 90 01 04 69 c6 05 90 01 04 63 90 02 0a c6 05 90 01 04 72 c6 05 90 01 04 56 c6 05 90 01 04 72 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GP_MTB_7{
	meta:
		description = "Trojan:Win32/Raccrypt.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {b0 65 b1 6c 68 90 01 09 c6 05 90 01 04 72 c6 05 90 01 04 2e c6 05 90 01 04 64 90 01 06 c6 05 90 01 04 00 90 02 14 c6 05 90 01 04 33 c6 05 90 01 04 32 90 02 05 c6 05 90 01 04 6b ff 15 90 00 } //01 00 
		$a_02_1 = {53 b3 6c 68 90 01 04 c6 05 90 01 04 65 c6 05 90 01 04 72 c6 05 90 01 04 2e c6 05 90 01 04 64 90 02 06 c6 05 90 01 04 00 c6 05 90 01 04 65 88 1d 90 01 04 c6 05 90 01 04 33 c6 05 90 01 04 32 90 02 06 c6 05 90 01 04 6e c6 05 90 01 04 6b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GP_MTB_8{
	meta:
		description = "Trojan:Win32/Raccrypt.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {cc b0 65 68 90 02 0a c6 05 90 01 04 72 c6 05 90 01 04 2e c6 05 90 01 04 64 c6 05 90 01 04 6c c6 05 90 01 04 00 c6 05 90 01 04 6e 90 02 05 c6 05 90 01 04 6c c6 05 90 01 04 33 c6 05 90 01 04 32 90 02 05 c6 05 90 01 04 6b ff 15 90 00 } //01 00 
		$a_02_1 = {b0 74 c6 05 90 01 04 00 c6 05 90 01 04 50 c6 05 90 01 04 61 c6 05 90 01 04 6f 90 02 05 c6 05 90 01 04 75 c6 05 90 01 04 6c c6 05 90 01 04 69 c6 05 90 01 04 63 90 02 0a c6 05 90 01 04 72 c6 05 90 01 04 56 c6 05 90 01 04 72 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}