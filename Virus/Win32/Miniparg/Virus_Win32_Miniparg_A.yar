
rule Virus_Win32_Miniparg_A{
	meta:
		description = "Virus:Win32/Miniparg.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {8d 44 24 40 50 68 90 01 04 ff 15 90 01 04 83 f8 ff 89 44 24 08 0f 84 90 01 02 00 00 53 55 8b 2d 90 01 04 56 57 6a 00 68 80 00 00 00 6a 03 6a 00 6a 03 8d 8c 24 90 90 00 00 00 68 00 00 00 c0 90 00 } //01 00 
		$a_02_1 = {f3 ab 66 ab 6a 00 52 8d 44 24 3c 6a 1a 50 56 ff 15 90 01 04 8d 4c 24 34 68 90 01 04 51 e8 90 01 02 00 00 83 c4 08 90 00 } //01 00 
		$a_02_2 = {51 8d 54 24 2c 68 90 01 04 52 e8 90 01 02 00 00 83 c4 20 8d 44 24 14 6a 00 68 82 00 00 00 6a 02 6a 00 6a 02 68 00 00 00 40 50 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}