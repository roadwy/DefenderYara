
rule Trojan_Win32_DelfInject_MA_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {3e 5a 2d 24 46 5a 2d 24 3e 5a 09 00 33 4c 3a 34 2f 48 3e 38 9b 4e 38 32 91 4a 09 00 62 7e 09 56 bb 0c 7d 75 c3 12 48 6c c6 11 6a 00 62 7e 09 00 62 7e 5f 69 90 0a 7c 61 86 38 7b 65 87 7e 09 } //01 00 
		$a_00_1 = {2a de 09 10 da b9 14 f8 21 01 f2 04 f6 68 83 4d 6b 07 4c f8 d8 ca f3 c0 4b 7b 89 e1 61 3e e9 02 60 46 83 45 4b 07 44 fc e8 48 c9 e9 60 fe e7 0f 22 5f 0a 0a 0a 0a 0d c0 40 7d 0b c8 60 c9 f2 4e } //01 00 
		$a_01_2 = {43 74 72 6c 2b } //01 00 
		$a_01_3 = {73 68 75 74 64 6f 77 6e } //01 00 
		$a_01_4 = {67 65 74 70 72 6f 74 6f 62 79 6e 75 6d 62 65 72 } //01 00 
		$a_01_5 = {57 53 41 55 6e 68 6f 6f 6b 42 6c 6f 63 6b 69 6e 67 48 6f 6f 6b } //01 00 
		$a_01_6 = {47 65 74 4b 65 79 53 74 61 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}