
rule Trojan_Win32_Raccrypt_GA_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {51 ba 6b 00 00 00 6a 00 c7 05 90 01 04 6e 00 65 00 c7 05 90 01 04 6c 00 33 00 66 89 15 90 01 04 a3 90 01 04 ff 15 90 0a 58 00 2e 00 00 00 90 01 01 72 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GA_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {6a 40 ff 35 90 01 04 c6 05 90 01 04 75 90 02 06 c6 05 90 01 04 6c 90 02 07 c6 05 90 01 04 63 c6 05 90 01 04 74 c6 05 90 01 04 74 c6 05 90 01 04 72 c6 05 90 01 04 69 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GA_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {b8 3b 2d 0b 00 01 45 90 01 01 8b 45 90 01 01 8a 04 08 88 04 31 41 3b 0d 90 00 } //0a 00 
		$a_00_1 = {81 00 47 86 c8 61 c3 c1 e0 04 89 01 c3 31 08 c3 33 44 24 04 c2 04 00 81 00 fe 36 ef c6 c3 01 08 c3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GA_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8d 4d fc 51 90 0a 8c 00 c6 05 90 01 04 65 c6 05 90 01 04 69 c6 05 90 01 04 75 c6 05 90 01 04 6c c6 05 90 01 04 63 c6 05 90 01 04 50 c6 05 90 01 04 61 c6 05 90 01 04 6f c6 05 90 01 04 74 c6 05 90 01 04 56 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GA_MTB_5{
	meta:
		description = "Trojan:Win32/Raccrypt.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {45 f8 40 00 00 00 c6 05 90 01 04 7f c6 05 90 01 05 c6 05 90 01 05 c6 05 90 01 04 50 c6 05 90 01 04 76 c6 05 90 01 04 72 c6 05 90 01 04 6f c6 05 90 01 04 63 c6 05 90 01 04 65 90 00 } //01 00 
		$a_00_1 = {6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GA_MTB_6{
	meta:
		description = "Trojan:Win32/Raccrypt.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {45 00 c6 05 90 01 04 75 90 02 06 c6 05 90 01 04 6c c6 05 90 01 04 74 c6 05 90 01 04 65 c6 05 90 01 04 63 c6 05 90 01 04 74 c6 05 90 01 04 72 c6 05 90 01 04 69 ff 15 90 00 } //0a 00 
		$a_02_1 = {6a 40 ff 35 90 01 04 c6 05 90 01 04 75 90 02 06 c6 05 90 01 04 6c c6 05 90 01 04 74 c6 05 90 01 04 65 c6 05 90 01 04 63 c6 05 90 01 04 74 c6 05 90 01 04 72 c6 05 90 01 04 69 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GA_MTB_7{
	meta:
		description = "Trojan:Win32/Raccrypt.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {50 6a 40 ff 35 90 01 04 c6 05 90 01 04 6f 90 02 06 c6 05 90 01 04 74 c6 05 90 01 04 00 c6 05 90 01 04 50 c6 05 90 01 04 61 c6 05 90 01 04 65 c6 05 90 01 04 75 c6 05 90 01 04 6c c6 05 90 01 04 69 c6 05 90 01 04 63 c6 05 90 01 04 74 c6 05 90 01 04 74 c6 05 90 01 04 72 c6 05 90 01 04 56 c6 05 90 01 04 72 ff 15 90 00 } //01 00 
		$a_02_1 = {55 8b ec 51 90 02 07 c6 05 90 01 04 65 c6 05 90 01 04 72 c6 05 90 01 04 2e c6 05 90 01 04 64 c6 05 90 01 04 6c c6 05 90 01 04 00 c6 05 90 01 04 33 c6 05 90 01 04 32 c6 05 90 01 04 6e c6 05 90 01 04 6b c6 05 90 01 04 6c c6 05 90 01 04 65 c6 05 90 01 04 6c ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}