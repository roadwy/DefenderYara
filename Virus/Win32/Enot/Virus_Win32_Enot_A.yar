
rule Virus_Win32_Enot_A{
	meta:
		description = "Virus:Win32/Enot.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {9c 51 8b 5d 08 b9 a6 18 00 00 8d b3 90 01 04 81 3e eb 02 41 44 75 08 83 c6 0f 83 e9 0f e2 f0 8a 06 34 42 88 06 46 e2 e7 59 9d 90 00 } //01 00 
		$a_00_1 = {56 57 53 55 9c 8b 7d 08 03 7f 3c 83 c7 04 83 c7 14 81 7f 34 1e f1 ad 0b 75 0e b8 01 00 00 00 9d 5d 5b 5f 5e } //01 00 
		$a_00_2 = {50 8b 7d e4 b9 28 00 00 00 b0 00 f3 aa 8b 7d e4 c7 07 2e 74 6c 73 8b 75 f4 8b 46 24 89 47 08 8f 47 0c 57 8b f0 56 8b 75 f4 8b 46 24 } //00 00 
	condition:
		any of ($a_*)
 
}