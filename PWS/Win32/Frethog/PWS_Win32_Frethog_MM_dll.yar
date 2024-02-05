
rule PWS_Win32_Frethog_MM_dll{
	meta:
		description = "PWS:Win32/Frethog.MM!dll,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 d2 8a 0c 10 80 c1 88 80 f1 77 80 e9 88 88 0c 10 42 81 fa 11 01 00 00 } //01 00 
		$a_01_1 = {c6 04 03 e9 40 8b ca c1 e9 00 80 e1 ff 88 0c 03 40 8b ca c1 e9 08 80 e1 ff 88 0c 03 40 8b ca c1 e9 10 80 e1 ff 88 0c 03 40 c1 ea 18 } //01 00 
		$a_01_2 = {b8 c0 e2 90 00 c6 00 44 b8 c1 e2 90 00 } //01 00 
		$a_03_3 = {6a 02 6a 00 68 ef fe ff ff 53 e8 90 01 02 ff ff 6a 00 68 90 01 02 40 00 68 11 01 00 00 90 00 } //01 00 
		$a_01_4 = {67 61 6d 65 2e 44 6f 50 61 74 63 68 } //00 00 
	condition:
		any of ($a_*)
 
}