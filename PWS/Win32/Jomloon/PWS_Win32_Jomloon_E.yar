
rule PWS_Win32_Jomloon_E{
	meta:
		description = "PWS:Win32/Jomloon.E,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 06 00 00 03 00 "
		
	strings :
		$a_01_0 = {50 51 8b 45 08 8b 4d 0c d2 c8 89 45 08 59 58 8a 45 08 } //01 00 
		$a_03_1 = {bb 00 10 40 00 8b 90 02 06 75 90 01 01 8b 90 03 02 03 45 a4 4c 24 5c 90 00 } //01 00 
		$a_03_2 = {c6 44 1e 09 e9 e8 90 01 04 80 7d 00 e8 75 17 8b 56 0a 8d 44 3a 05 90 00 } //01 00 
		$a_03_3 = {c6 40 09 e9 83 c0 0a 50 e8 90 02 08 80 90 01 01 09 e8 75 15 8b 90 01 01 0a 8d 44 90 01 01 05 90 00 } //01 00 
		$a_03_4 = {99 01 00 00 8a 90 01 01 98 01 00 00 33 90 01 01 51 8a 90 01 01 97 01 00 00 90 00 } //01 00 
		$a_01_5 = {0f b6 86 99 01 00 00 50 0f b6 86 98 01 00 00 50 0f b6 86 97 01 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}