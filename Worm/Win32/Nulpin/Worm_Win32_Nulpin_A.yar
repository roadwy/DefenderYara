
rule Worm_Win32_Nulpin_A{
	meta:
		description = "Worm:Win32/Nulpin.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {eb ea 3b c1 75 12 83 f9 40 73 0d } //03 00 
		$a_03_1 = {74 1f 8a 0c 32 8a c2 2c 90 01 01 8b fe d0 e0 02 c8 33 c0 88 0c 32 83 c9 ff 42 f2 ae f7 d1 49 3b d1 72 e1 90 00 } //01 00 
		$a_01_2 = {6d 73 63 6f 6e 67 6d 75 74 65 78 00 } //01 00 
		$a_01_3 = {73 75 63 68 6f 74 73 2e 65 78 65 00 } //01 00 
		$a_01_4 = {47 45 54 20 2f 4e 55 4c 4c 2e 70 72 69 6e 74 65 72 0a 00 } //00 00 
	condition:
		any of ($a_*)
 
}