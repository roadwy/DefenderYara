
rule Backdoor_Win32_Popwin_gen_E{
	meta:
		description = "Backdoor:Win32/Popwin.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,19 00 15 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //0a 00 
		$a_00_1 = {44 65 6c 65 74 65 55 72 6c 43 61 63 68 65 45 6e 74 72 79 } //01 00 
		$a_01_2 = {3d 2b 05 00 00 73 07 b8 e6 73 3e 02 c9 c3 83 f8 f0 76 0b 33 d2 b9 00 e1 f5 05 f7 f1 8b c2 c9 c3 } //05 00 
		$a_01_3 = {8a 55 10 8d 84 0d fc fe ff ff 2a d1 8a 1c 06 32 da 41 3b 4d 10 88 18 7c e7 } //9c ff 
		$a_00_4 = {77 77 77 2e 33 36 30 2e 63 6e } //9c ff 
		$a_00_5 = {33 36 30 73 61 66 65 75 70 6c 6f 61 64 5f 6d 75 74 65 78 } //00 00 
	condition:
		any of ($a_*)
 
}