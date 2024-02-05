
rule Trojan_Win32_Raccrypt_GV_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 44 24 90 01 01 c7 05 90 01 04 ee 3d ea f4 8b 44 24 90 02 0a 90 17 02 01 01 31 33 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GV_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {bd a3 53 78 c7 84 24 90 01 06 c4 0d c7 84 24 90 01 04 c5 00 1d 75 c7 84 24 90 01 04 84 50 74 21 c7 84 24 90 01 04 08 d3 e3 58 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GV_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {25 bb 52 c0 5d 8b 90 02 0a c1 90 01 01 04 03 90 02 1e c1 90 02 01 05 03 90 02 0f 90 17 02 01 01 31 33 90 02 0a 8b 45 90 01 01 29 45 90 02 0f 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GV_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {51 6a 40 ff 35 90 0a 96 00 6c c6 05 90 01 04 6c 90 02 06 c6 05 90 01 04 6b 90 02 07 c6 05 90 01 04 72 c6 05 90 01 04 6c c6 05 90 01 04 32 c6 05 90 01 04 2e c6 05 90 01 04 6e c6 05 90 01 04 65 c6 05 90 01 04 64 c6 05 90 01 04 33 90 02 07 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GV_MTB_5{
	meta:
		description = "Trojan:Win32/Raccrypt.GV!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 00 e1 34 ef c6 c3 } //01 00 
		$a_01_1 = {01 08 c3 29 08 c3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GV_MTB_6{
	meta:
		description = "Trojan:Win32/Raccrypt.GV!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 00 eb 34 ef c6 c3 } //01 00 
		$a_01_1 = {01 08 c3 29 08 c3 } //00 00 
	condition:
		any of ($a_*)
 
}