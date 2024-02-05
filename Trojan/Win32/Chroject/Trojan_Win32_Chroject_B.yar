
rule Trojan_Win32_Chroject_B{
	meta:
		description = "Trojan:Win32/Chroject.B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {83 46 14 02 89 7e 08 8b 46 10 03 46 08 88 18 ff 46 10 8b 4e 10 8b 46 14 3b c8 } //02 00 
		$a_01_1 = {8b 04 01 3d 6c 6f 77 69 75 } //02 00 
		$a_01_2 = {ff d6 33 d2 b9 0a 00 00 00 f7 f1 83 c2 14 69 d2 b8 0b 00 00 52 ff d7 ff d6 2b c3 } //01 00 
		$a_01_3 = {78 65 6e 76 64 62 00 } //01 00 
		$a_01_4 = {76 6d 69 63 65 78 63 68 61 6e 67 65 00 } //00 00 
		$a_00_5 = {5d 04 00 00 b6 } //23 03 
	condition:
		any of ($a_*)
 
}