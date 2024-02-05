
rule PWS_Win32_Frethog_AP{
	meta:
		description = "PWS:Win32/Frethog.AP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {68 00 28 00 00 53 89 08 c7 40 04 c8 00 00 00 c7 40 08 44 18 00 00 ff 15 90 01 04 5b c3 56 8b 74 24 08 6a 01 56 ff 15 90 01 04 85 c0 75 3f 81 3e 7a 6f 6e 67 75 90 00 } //01 00 
		$a_03_1 = {7e 18 8b 54 24 0c 53 8b ce 2b d6 8b f8 8a 1c 0a 80 f3 90 01 01 88 19 41 48 75 f4 5b 80 24 37 00 90 00 } //01 00 
		$a_03_2 = {8d 7d f9 c6 45 f8 e9 b9 90 01 04 ab a1 90 01 04 6a 05 2b c8 5e 2b ce 56 90 00 } //01 00 
		$a_01_3 = {c7 45 f0 4c 6f 67 69 c7 45 f4 6e 5f 53 65 c7 45 f8 72 76 65 72 ff d6 } //00 00 
	condition:
		any of ($a_*)
 
}