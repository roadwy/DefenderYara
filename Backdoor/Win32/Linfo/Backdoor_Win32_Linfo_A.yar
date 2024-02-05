
rule Backdoor_Win32_Linfo_A{
	meta:
		description = "Backdoor:Win32/Linfo.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 7d f4 03 7d f8 8a 07 c0 c8 05 34 21 88 07 41 3b ce 89 4d f8 7c e9 } //01 00 
		$a_01_1 = {5c 74 70 2e 64 61 74 00 00 00 65 78 46 6f 72 6d 00 00 6c 69 6e 6b 69 6e 66 6f 2e 64 6c 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Linfo_A_2{
	meta:
		description = "Backdoor:Win32/Linfo.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 5c 73 6d 65 72 70 30 2e 64 62 6c } //01 00 
		$a_01_1 = {50 4f 53 54 20 68 74 74 70 3a 2f 2f 25 73 3a 25 73 2f 62 6b 73 2e 61 73 70 } //01 00 
		$a_03_2 = {c7 45 e0 4a 53 50 72 c7 45 e4 6f 78 79 2e c7 45 e8 64 6c 6c 00 c7 45 ec 00 00 00 00 8d 75 e0 56 8b 5d b4 8d 93 90 01 04 b8 a4 00 00 00 03 d0 ff 12 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}