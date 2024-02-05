
rule Trojan_Win32_Redline_MD_MTB{
	meta:
		description = "Trojan:Win32/Redline.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 10 8b 44 24 14 03 44 24 90 01 01 c7 05 90 01 04 00 00 00 00 33 90 01 01 33 90 01 01 2b 90 01 01 89 44 24 14 8b 90 01 01 c1 e0 04 89 44 24 10 8b 44 24 2c 01 44 24 10 81 3d 90 01 04 be 01 00 00 8d 90 01 02 75 0e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_MD_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {31 c0 29 c8 88 84 24 97 01 00 00 0f b6 84 24 97 01 00 00 83 e8 24 88 84 24 97 01 00 00 8b 8c 24 98 01 00 00 0f b6 84 24 97 01 00 00 31 c8 88 84 24 97 01 00 00 0f b6 84 24 97 01 00 00 83 f0 ff 88 84 24 97 01 00 00 0f b6 8c 24 97 01 00 00 31 c0 29 c8 88 84 24 97 01 00 00 8a 8c 24 97 01 00 00 8b 84 24 98 01 00 00 88 8c 04 9d 01 00 00 8b 84 24 98 01 00 00 83 c0 01 89 84 24 98 01 00 00 e9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_MD_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 55 f4 83 c2 01 89 55 f4 8b 45 f4 3b 45 10 73 90 01 01 8b 4d fc 03 4d f4 8b 55 f8 03 55 f4 8a 02 88 01 eb 90 00 } //01 00 
		$a_01_1 = {71 75 65 79 61 6c 6f 64 74 61 6b 65 79 74 69 6b 65 70 69 63 69 } //01 00 
		$a_01_2 = {52 65 66 69 63 65 20 6a 61 72 65 77 20 64 69 6a 6f 73 20 6c 69 76 20 71 75 6f 6a 6f 6b } //01 00 
		$a_01_3 = {43 72 65 61 74 65 4d 75 74 65 78 57 } //01 00 
		$a_01_4 = {47 65 74 43 50 49 6e 66 6f 45 78 41 } //01 00 
		$a_01_5 = {43 6c 69 65 6e 74 54 6f 53 63 72 65 65 6e } //00 00 
	condition:
		any of ($a_*)
 
}