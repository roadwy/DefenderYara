
rule Trojan_Win32_Kryptik_GA_MTB{
	meta:
		description = "Trojan:Win32/Kryptik.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {88 44 24 28 8b 13 8a 44 24 28 8b f1 33 ed 03 f2 8a 16 3a d0 75 1f 8b c7 8b fe 2b 7c 24 2c 84 d2 74 0f 80 38 00 74 } //01 00 
		$a_02_1 = {8b 75 d8 81 fe 00 00 00 01 77 9b c7 05 90 01 04 50 72 6f 63 c7 05 90 01 04 65 73 73 33 c7 05 90 01 04 32 46 69 72 66 c7 05 90 01 04 73 74 68 90 01 04 56 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Kryptik_GA_MTB_2{
	meta:
		description = "Trojan:Win32/Kryptik.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 0c 30 a1 90 01 04 88 0c 30 a1 90 01 04 3d 90 01 04 75 90 00 } //01 00 
		$a_02_1 = {8a 54 19 02 8a 4c 19 03 88 8d 90 01 04 80 e1 90 01 01 c0 e1 90 01 01 88 95 90 01 04 88 8d 90 01 04 83 f8 90 01 01 75 90 00 } //01 00 
		$a_02_2 = {24 fc c0 e0 90 01 01 c0 e1 90 01 01 0a d0 08 8d 90 01 04 88 34 3e 81 3d 90 02 08 88 95 90 01 04 75 90 00 } //01 00 
		$a_02_3 = {8b c7 c1 e8 90 01 01 03 85 90 01 04 33 c3 33 c2 2b f0 83 90 02 06 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}