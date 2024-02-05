
rule Backdoor_Win32_Remcos_MM_MTB{
	meta:
		description = "Backdoor:Win32/Remcos.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 01 0f b7 00 f6 c4 f9 74 1e 8b 1d 90 01 04 8b 1b 03 1d 90 01 04 66 25 ff 0f 0f b7 c0 03 d8 a1 90 01 04 01 03 83 01 02 ff 05 90 01 04 4a 75 cc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Remcos_MM_MTB_2{
	meta:
		description = "Backdoor:Win32/Remcos.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //0a 00 
		$a_01_1 = {25 f0 07 00 00 66 0f 28 a0 80 09 46 00 66 0f 28 b8 70 05 46 00 66 0f 54 f0 66 0f 5c c6 66 0f 59 f4 66 0f 5c f2 f2 0f 58 fe 66 0f 59 c4 66 0f 28 e0 } //02 00 
		$a_01_2 = {52 65 6d 63 6f 73 20 72 65 73 74 61 72 74 65 64 20 62 79 20 77 61 74 63 68 64 6f 67 21 } //00 00 
		$a_00_3 = {78 a2 00 00 06 00 06 00 06 00 00 01 } //00 13 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Remcos_MM_MTB_3{
	meta:
		description = "Backdoor:Win32/Remcos.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {73 74 75 62 5c 55 6f 70 79 45 78 5c 61 63 68 69 69 4d 65 } //01 00 
		$a_81_1 = {67 65 74 5f 49 73 36 34 42 69 74 4f 70 65 72 61 74 69 6e 67 53 79 73 74 65 6d } //01 00 
		$a_81_2 = {78 6c 40 7a 43 6e 3d 6d 74 5d 73 6b 5d } //01 00 
		$a_81_3 = {47 65 74 45 6e 74 72 79 41 73 73 65 6d 62 6c 79 } //01 00 
		$a_81_4 = {43 72 65 61 74 65 46 72 6f 6d 55 72 6c } //01 00 
		$a_00_5 = {24 31 35 55 45 41 45 44 43 2d 45 41 30 30 2d 34 35 48 38 2d 38 44 36 37 3f 38 42 44 37 43 43 54 45 41 43 37 30 } //00 00 
	condition:
		any of ($a_*)
 
}