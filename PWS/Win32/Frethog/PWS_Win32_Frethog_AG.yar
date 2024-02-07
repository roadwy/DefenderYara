
rule PWS_Win32_Frethog_AG{
	meta:
		description = "PWS:Win32/Frethog.AG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {00 68 6f 6f 6b 20 64 6c 6c 20 72 69 73 69 6e 67 00 } //01 00 
		$a_00_1 = {00 43 4c 53 49 44 5c 4e 4f 44 33 32 4b 56 42 49 54 00 } //01 00  䌀卌䑉乜䑏㈳噋䥂T
		$a_01_2 = {8b 4d 14 8b 55 10 c7 00 1f 00 00 00 56 8b 01 03 c2 0f b6 50 03 0f b6 70 02 c1 e2 08 03 d6 0f b6 70 01 0f b6 00 c1 e2 08 03 d6 5e c1 e2 08 03 d0 8b 45 08 89 10 83 01 04 8b 00 c1 e8 1f 5d c2 10 00 } //00 00 
	condition:
		any of ($a_*)
 
}