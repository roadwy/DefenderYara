
rule Trojan_Win32_Emotet_RF_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {61 72 7a 74 6f 65 6c 61 6f 67 68 77 75 71 67 } //01 00 
		$a_81_1 = {62 76 61 77 6e 6c 66 6d 71 64 71 67 67 76 72 69 } //01 00 
		$a_81_2 = {64 78 62 6a 71 71 7a 76 67 77 65 79 78 69 62 7a } //01 00 
		$a_81_3 = {67 67 70 74 6c 68 67 6b 76 64 64 70 79 70 71 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_80_0 = {64 66 3f 2a 61 33 74 72 37 6d 78 36 42 4a 72 73 37 3c 66 62 54 25 59 28 64 75 4a 28 4d 76 6a 52 40 30 64 41 62 35 21 51 6d 36 37 29 36 43 4b 76 77 55 68 37 4f 55 72 30 55 5f 72 58 46 68 4f 77 54 29 24 6b 48 39 71 77 24 55 40 6b } //df?*a3tr7mx6BJrs7<fbT%Y(duJ(MvjR@0dAb5!Qm67)6CKvwUh7OUr0U_rXFhOwT)$kH9qw$U@k  01 00 
		$a_03_1 = {83 c5 40 55 68 00 30 00 00 56 53 6a ff ff 15 90 01 04 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_RF_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 01 00 "
		
	strings :
		$a_81_0 = {28 5e 74 4d 4b 26 31 36 76 34 41 32 48 53 21 24 70 71 4b 76 43 53 30 41 57 3c 76 6e 6c 6e 6a 69 76 52 53 50 36 6d 4d 31 65 4e 32 53 71 6e 47 63 53 29 2a 6d 5a 73 6f 37 4d 45 57 4c 52 77 6b 6d 6b 49 31 } //05 00 
		$a_03_1 = {33 c2 8b 0d 90 01 04 0f af 0d 90 01 04 0f af 0d 90 01 04 8b 15 90 01 04 0f af 15 90 01 04 8b 75 90 01 01 2b f2 2b f1 03 35 90 01 04 03 35 90 01 04 8b 4d 90 01 01 88 04 31 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}