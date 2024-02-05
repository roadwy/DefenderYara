
rule PWS_Win32_Frethog_MR{
	meta:
		description = "PWS:Win32/Frethog.MR,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 07 00 06 00 00 05 00 "
		
	strings :
		$a_03_0 = {78 f8 ff ff e9 90 09 0d 00 2b 90 01 01 83 90 01 01 05 89 90 01 01 74 f8 ff ff c6 85 90 00 } //05 00 
		$a_01_1 = {c7 85 70 f8 ff ff 20 00 00 e0 } //02 00 
		$a_01_2 = {b8 64 6c 6c 00 } //02 00 
		$a_01_3 = {68 64 6c 6c 00 } //01 00 
		$a_01_4 = {25 73 5c 77 69 6e 5f 25 64 2e 6c 6f 67 00 } //01 00 
		$a_01_5 = {49 44 52 5f 44 4c 4c 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule PWS_Win32_Frethog_MR_2{
	meta:
		description = "PWS:Win32/Frethog.MR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 03 00 "
		
	strings :
		$a_03_0 = {53 8a 1c 08 80 f3 90 01 01 88 1c 08 40 3b c2 72 f2 90 00 } //01 00 
		$a_00_1 = {25 73 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 25 73 } //01 00 
		$a_02_2 = {5c 73 79 73 74 65 6d 53 65 74 55 70 2e 69 6e 66 90 02 05 25 63 25 73 25 63 90 02 05 5c 72 75 6e 2e 62 61 74 90 00 } //01 00 
		$a_00_3 = {25 73 3f 6e 3d 25 73 26 70 3d 25 73 26 6c 3d 25 73 } //01 00 
		$a_01_4 = {4a 4d 56 5f 56 4d 4a 00 } //01 00 
		$a_02_5 = {2e 69 6e 69 90 02 05 54 53 53 61 66 65 45 64 69 74 2e 64 61 74 90 02 05 4c 6f 67 69 6e 43 74 72 6c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}