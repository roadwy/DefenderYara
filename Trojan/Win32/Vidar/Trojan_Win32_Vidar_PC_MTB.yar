
rule Trojan_Win32_Vidar_PC_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 88 8d 0c 07 33 d2 8b c7 f7 f3 8b 85 90 01 04 56 8a 04 02 8b 55 84 32 04 0a 88 01 90 00 } //01 00 
		$a_03_1 = {2b c1 89 45 90 01 01 8b 45 90 01 01 8d 0c 90 01 01 33 d2 8b c3 f7 75 90 01 01 8b 85 90 01 04 57 8a 04 02 8b 55 84 32 04 0a 88 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Vidar_PC_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.PC!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 73 74 61 72 74 20 2f 42 20 70 6f 77 65 72 73 68 65 6c 6c 20 2d 77 69 6e 64 6f 77 73 74 79 6c 65 20 68 69 64 64 65 6e 20 2d 63 6f 6d 6d 61 6e 64 } //01 00 
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 66 75 63 6b 5c } //01 00 
		$a_01_2 = {67 61 74 65 31 2e 70 68 70 3f 61 3d 7b 62 62 65 64 33 65 35 35 36 35 36 67 68 66 30 32 2d 30 62 34 31 2d 31 31 65 33 2d 38 32 34 39 7d 69 64 3d 32 } //01 00 
		$a_01_3 = {77 6f 2e 70 68 70 3f 73 74 75 62 3d } //00 00 
	condition:
		any of ($a_*)
 
}