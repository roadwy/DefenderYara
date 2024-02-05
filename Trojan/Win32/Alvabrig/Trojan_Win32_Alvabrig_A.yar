
rule Trojan_Win32_Alvabrig_A{
	meta:
		description = "Trojan:Win32/Alvabrig.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 7a 03 64 6f 77 73 75 3f 8b 45 0c 25 ff 00 00 00 } //01 00 
		$a_03_1 = {8b 40 04 91 c1 e9 02 81 30 90 01 04 c1 00 02 83 c0 04 e2 f2 90 00 } //01 00 
		$a_03_2 = {b0 e8 f2 ae 0b c9 74 90 01 01 8b c2 2b c7 39 07 75 f0 90 00 } //02 00 
		$a_03_3 = {01 4d 20 01 4d 50 01 8d a4 00 00 00 90 09 05 00 b9 90 00 } //01 00 
		$a_03_4 = {c1 e9 02 39 18 74 11 81 38 90 01 04 74 09 81 30 90 01 04 c1 00 02 83 c0 04 90 02 02 e2 90 00 } //01 00 
		$a_01_5 = {b0 68 ba 6f 73 74 73 be 6f 73 6d 73 8b 7d fc 83 e9 } //01 00 
		$a_03_6 = {4a 8a 07 32 c1 03 c9 fe c1 aa 4a 75 f4 8b 3d 90 01 04 8b cf b0 50 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}