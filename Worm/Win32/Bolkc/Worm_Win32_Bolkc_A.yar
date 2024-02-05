
rule Worm_Win32_Bolkc_A{
	meta:
		description = "Worm:Win32/Bolkc.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 45 f4 33 c9 8a 4c 10 01 c1 f9 03 88 8d 5c ff ff ff 8b 55 f8 6b d2 03 8b 45 f4 } //02 00 
		$a_03_1 = {49 4e 33 44 43 4c 41 53 53 00 00 90 09 11 00 73 76 63 68 6f 73 74 90 00 } //01 00 
		$a_01_2 = {6f 6c 65 67 2d 2d 6e } //01 00 
		$a_01_3 = {3f 5c 44 50 28 3f 29 3f 2d 3f 2b 3f 3f } //00 00 
	condition:
		any of ($a_*)
 
}