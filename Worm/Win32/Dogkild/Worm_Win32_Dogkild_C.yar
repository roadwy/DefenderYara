
rule Worm_Win32_Dogkild_C{
	meta:
		description = "Worm:Win32/Dogkild.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 03 00 "
		
	strings :
		$a_01_0 = {8b f0 c1 ee 19 c1 e0 07 0b f0 0f be c1 8a 4a 01 33 c6 42 84 c9 75 e9 } //03 00 
		$a_01_1 = {73 14 8b 45 fc 03 45 f8 8a 00 2c 01 8b 4d fc 03 4d f8 88 01 eb } //01 00 
		$a_01_2 = {68 14 20 22 00 } //03 00 
		$a_01_3 = {83 ff 31 7e 05 83 ef 32 eb 03 83 c7 0a } //01 00 
		$a_01_4 = {5c 5c 2e 5c 70 63 69 64 75 6d 70 00 } //01 00 
		$a_00_5 = {5c 64 72 69 76 65 72 73 5c 41 73 79 6e 63 4d 61 63 2e 73 79 73 } //01 00 
		$a_00_6 = {74 61 73 6b 6b 69 6c 6c 2e 65 78 65 20 2f 69 6d } //00 00 
	condition:
		any of ($a_*)
 
}