
rule Worm_Win32_Dorkbot_A_{
	meta:
		description = "Worm:Win32/Dorkbot.A!!Dorkbot.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 67 72 42 6f 74 } //01 00 
		$a_00_1 = {6e 67 72 2d 3e 62 6c 6f 63 6b 73 69 7a 65 3a 20 25 64 } //01 00 
		$a_00_2 = {5b 52 75 73 6b 69 6c 6c 5d 3a 20 44 65 74 65 63 74 65 64 20 } //01 00 
		$a_02_3 = {5b 53 6c 6f 77 6c 6f 72 69 73 5d 3a 20 90 01 08 20 66 6c 6f 6f 64 20 6f 6e 20 22 25 73 22 90 00 } //01 00 
		$a_00_4 = {5b 50 44 65 66 2b 5d 3a 20 25 73 } //05 00 
	condition:
		any of ($a_*)
 
}