
rule Backdoor_Win32_Tofsee_gen_B{
	meta:
		description = "Backdoor:Win32/Tofsee.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 06 00 00 05 00 "
		
	strings :
		$a_03_0 = {c6 45 f3 a5 8b 45 08 89 45 fc 8b 4d fc 03 4d 0c 89 4d f4 8b 55 fc 3b 55 f4 73 90 01 01 8b 45 fc 0f b6 08 89 4d f8 8b 55 f8 c1 e2 08 0b 55 f8 c1 ea 03 81 e2 ff 00 00 00 8b 45 fc 88 10 90 00 } //03 00 
		$a_01_1 = {67 68 65 67 64 6a 66 00 } //01 00 
		$a_00_2 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 73 65 74 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d 20 22 25 73 22 20 45 4e 41 42 4c 45 } //01 00 
		$a_01_3 = {5f 50 41 53 53 57 44 5f 00 } //01 00 
		$a_01_4 = {5f 41 43 43 5f 00 } //01 00 
		$a_01_5 = {68 74 74 70 25 73 3a 2f 2f 25 73 25 73 25 73 25 73 25 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}