
rule Virus_Win32_Tank_gen_A{
	meta:
		description = "Virus:Win32/Tank.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {e8 00 00 00 00 81 2c 24 60 19 00 00 58 8d 90 e1 19 00 00 52 8d 90 87 1b 00 00 52 64 67 ff 36 00 00 64 67 89 26 00 00 33 c0 8b 55 04 66 81 3a 4d 5a 75 53 8b 4a 3c 8d 0c 0a 81 39 50 45 00 00 75 45 } //01 00 
		$a_01_1 = {58 2d 54 61 6e 6b 20 62 79 20 53 68 61 64 6f 77 } //01 00 
		$a_01_2 = {58 2d 54 61 6e 6b 20 41 67 65 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}