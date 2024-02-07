
rule Worm_Win32_Zeagle_A{
	meta:
		description = "Worm:Win32/Zeagle.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff 51 38 ff 45 f8 ff 4d f4 75 b9 8d 55 e0 b8 } //01 00 
		$a_01_1 = {fe 45 f3 80 7d f3 5b 0f } //01 00 
		$a_01_2 = {3c 01 75 3c 8d 45 b0 50 8d 55 a8 8b 45 f8 e8 } //01 00 
		$a_01_3 = {6a 6f 65 62 6f 78 63 6f 6e 74 72 6f 6c 2e 65 78 65 00 } //01 00 
		$a_01_4 = {64 69 72 5f 77 61 74 63 68 2e 64 6c 6c 00 } //01 00 
		$a_01_5 = {77 65 62 64 6f 77 6e 00 } //00 00  敷摢睯n
	condition:
		any of ($a_*)
 
}