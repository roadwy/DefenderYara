
rule Ransom_Win32_Nokonoko_AD_MTB{
	meta:
		description = "Ransom:Win32/Nokonoko.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc9 00 ffffffc9 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //64 00 
		$a_03_1 = {8b fa 8b c2 c1 c7 90 01 01 c1 c0 90 01 01 33 f8 c1 ea 90 01 01 33 fa 8b c6 c1 c8 90 01 01 8b d6 c1 c2 90 01 01 33 c2 c1 ee 90 01 01 33 c6 05 90 01 04 03 c7 03 43 90 01 01 03 43 90 01 01 03 c1 41 89 43 90 01 01 81 f9 90 01 04 7c ba 90 00 } //64 00 
		$a_01_2 = {8d 4d a8 03 ca 42 8a 04 19 32 01 88 04 31 3b d7 72 ee } //00 00 
		$a_00_3 = {5d 04 00 00 91 93 05 80 5c 22 00 00 93 93 05 80 00 00 01 00 08 00 0c 00 ad 01 53 74 61 72 74 65 72 2e 44 4a 00 00 01 40 05 82 70 00 04 00 67 26 00 00 48 c0 45 5b 1c 88 0b d4 06 fa a3 ea 53 02 00 00 01 10 85 b4 7e 90 f5 47 81 98 a5 48 38 5b e7 00 23 d8 da d6 91 fc 5d 04 00 00 93 93 05 80 5c 22 00 00 94 93 05 80 00 00 01 00 08 00 0c 00 ac 21 57 69 6e 4c 4e 4b 2e 50 52 4c 00 00 03 40 05 82 70 00 04 00 67 26 00 00 e9 66 63 0d 66 32 b7 71 64 6e 58 3e cc 03 00 00 01 10 90 07 6d 5e ef 8f fb d6 39 aa ef ac 50 e7 62 26 d8 ed 1d 55 67 26 00 00 0d e5 f3 c3 24 bb 1d 08 26 e7 f2 47 cc 03 00 00 01 10 77 3a } //22 ed 
	condition:
		any of ($a_*)
 
}