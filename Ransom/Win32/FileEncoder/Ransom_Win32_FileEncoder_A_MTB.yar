
rule Ransom_Win32_FileEncoder_A_MTB{
	meta:
		description = "Ransom:Win32/FileEncoder.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {83 fa 10 75 02 33 d2 ac 32 82 90 01 04 aa 42 49 75 ed 90 00 } //01 00 
		$a_03_1 = {bb 01 00 00 00 d3 e3 23 d8 74 2d 80 c1 41 88 0d 90 01 04 80 e9 41 c7 05 90 01 04 3a 5c 2a 2e c6 05 90 01 04 2a c6 05 90 01 04 00 50 51 90 00 } //00 00 
		$a_00_2 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_FileEncoder_A_MTB_2{
	meta:
		description = "Ransom:Win32/FileEncoder.A!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 46 69 6c 65 } //01 00 
		$a_01_1 = {6d 61 69 6e 2e 6d 61 6b 65 42 61 74 46 69 6c 65 } //01 00 
		$a_01_2 = {6d 61 69 6e 2e 64 65 6c 65 74 65 53 68 61 64 6f 77 43 6f 70 79 } //01 00 
		$a_01_3 = {6d 61 69 6e 2e 72 65 62 6f 6f 74 } //01 00 
		$a_01_4 = {6d 61 69 6e 2e 72 61 6e 64 6f 6d 42 61 74 46 69 6c 65 4e 61 6d 65 } //01 00 
		$a_01_5 = {63 72 79 70 74 6f 2f 72 73 61 2e 65 6e 63 72 79 70 74 } //01 00 
		$a_01_6 = {6d 61 69 6e 2e 28 2a 6d 79 53 65 72 76 69 63 65 29 2e 45 78 65 63 75 74 65 } //01 00 
		$a_01_7 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //00 00 
	condition:
		any of ($a_*)
 
}