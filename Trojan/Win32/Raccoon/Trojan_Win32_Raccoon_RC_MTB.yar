
rule Trojan_Win32_Raccoon_RC_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 33 d2 b9 04 00 00 00 f7 f1 8b 45 10 0f b6 0c 10 8b 55 08 03 55 fc 0f b6 02 33 c1 8b 4d 08 03 4d fc 88 01 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccoon_RC_MTB_2{
	meta:
		description = "Trojan:Win32/Raccoon.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 c2 0c 00 90 02 25 01 45 fc 8b 45 08 8b 4d 90 01 01 31 08 c9 c2 08 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccoon_RC_MTB_3{
	meta:
		description = "Trojan:Win32/Raccoon.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {cc cc 81 01 e1 34 ef c6 c3 cc cc } //01 00 
		$a_03_1 = {89 44 24 14 8b 44 24 90 01 01 01 44 24 14 8b 4c 24 14 33 4c 24 28 8b 44 24 10 90 02 10 33 c1 2b f0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccoon_RC_MTB_4{
	meta:
		description = "Trojan:Win32/Raccoon.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 c2 08 00 55 8b ec 51 83 65 fc 00 8b 45 10 01 45 fc 8b 45 0c 33 45 fc 89 45 fc 8b 45 08 8b 4d fc 89 08 c9 c2 0c 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccoon_RC_MTB_5{
	meta:
		description = "Trojan:Win32/Raccoon.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {36 dd 96 53 81 45 90 01 01 38 dd 96 53 8b 4d 90 01 01 8b c6 d3 e0 90 02 15 03 c6 89 45 90 01 01 8b c6 d3 e8 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 31 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccoon_RC_MTB_6{
	meta:
		description = "Trojan:Win32/Raccoon.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {d3 e8 89 44 24 10 8b 44 24 4c 01 44 24 10 8b 4c 24 28 33 ca 89 4c 24 38 89 5c 24 30 8b 44 24 38 89 44 24 30 8b 44 24 10 31 44 24 30 } //01 00 
		$a_01_1 = {8b 44 24 14 01 44 24 28 8b 44 24 18 c1 e8 05 89 44 24 10 8b 44 24 10 33 74 24 28 03 44 24 48 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccoon_RC_MTB_7{
	meta:
		description = "Trojan:Win32/Raccoon.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 00 e1 34 ef c6 c3 01 08 c3 } //01 00 
		$a_03_1 = {ee 3d ea f4 89 45 90 02 10 33 7d 90 01 01 31 7d 90 02 50 81 6d 90 01 01 36 dd 96 53 81 45 90 01 01 3a dd 96 53 8b 45 90 01 01 8b 4d 90 02 0a d3 e8 90 02 20 8b c6 d3 e0 03 45 90 01 01 33 45 90 01 01 33 c2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccoon_RC_MTB_8{
	meta:
		description = "Trojan:Win32/Raccoon.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 00 47 86 c8 61 c3 81 00 e1 34 ef c6 c3 01 08 c3 01 08 c3 } //01 00 
		$a_03_1 = {ee 3d ea f4 89 45 90 02 10 33 75 90 01 01 31 75 90 02 50 81 6d 90 01 01 36 dd 96 53 81 45 90 01 01 3a dd 96 53 90 02 10 d3 e8 90 02 20 d3 e2 90 02 08 03 55 90 01 01 33 55 90 01 01 33 d6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccoon_RC_MTB_9{
	meta:
		description = "Trojan:Win32/Raccoon.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 00 e1 34 ef c6 c3 01 08 c3 } //01 00 
		$a_03_1 = {ee 3d ea f4 89 45 90 02 10 33 7d 90 01 01 31 7d 90 02 50 81 6d 90 01 01 36 dd 96 53 81 45 90 01 01 3a dd 96 53 8b 45 90 01 01 8b 4d 90 01 01 03 c6 8b d6 d3 e2 90 02 10 d3 e8 90 02 10 01 45 90 01 01 8b 45 90 01 01 33 45 90 02 0a 33 d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccoon_RC_MTB_10{
	meta:
		description = "Trojan:Win32/Raccoon.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {b1 6c b0 6d 90 02 08 88 0d 90 01 04 a2 90 01 04 c6 05 90 01 04 73 c6 05 90 01 04 69 c6 05 90 01 04 00 c6 05 90 01 04 33 c6 05 90 01 04 32 a2 90 01 04 c6 05 90 01 04 67 88 0d 90 01 04 c6 05 90 01 04 2e c6 05 90 01 04 64 ff 15 90 01 04 c3 cc cc 81 01 e1 34 ef c6 c3 cc cc 90 00 } //01 00 
		$a_03_1 = {81 6c 24 24 36 dd 96 53 81 44 24 24 3a dd 96 53 90 02 20 d3 e2 90 02 20 c1 e8 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}