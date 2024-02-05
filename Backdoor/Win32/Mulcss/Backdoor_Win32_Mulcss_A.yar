
rule Backdoor_Win32_Mulcss_A{
	meta:
		description = "Backdoor:Win32/Mulcss.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {80 3c 24 0a 74 21 80 3c 24 ac 75 0e 80 7c 24 01 10 72 07 80 7c 24 01 1f } //01 00 
		$a_00_1 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b } //01 00 
		$a_00_2 = {bc e0 cc fd b5 c4 b6 cb bf da ba c5 ce aa 30 21 } //01 00 
		$a_00_3 = {73 63 20 63 6f 6e 66 69 67 20 55 49 30 44 65 74 65 63 74 20 73 74 61 72 74 3d 20 64 69 73 61 62 6c 65 64 } //01 00 
		$a_00_4 = {00 64 65 6c 20 25 30 00 } //01 00 
		$a_00_5 = {53 4f 46 54 57 41 52 45 5c 4f 44 42 43 5c 53 51 4c 4c 65 76 65 6c } //00 00 
	condition:
		any of ($a_*)
 
}