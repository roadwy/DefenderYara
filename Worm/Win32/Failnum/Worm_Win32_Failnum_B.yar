
rule Worm_Win32_Failnum_B{
	meta:
		description = "Worm:Win32/Failnum.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 75 63 6b 69 6e 67 20 66 61 69 6c 20 33 } //01 00 
		$a_01_1 = {42 61 77 74 42 6f 74 20 3b 2d 2d 70 } //01 00 
		$a_01_2 = {ff ff de c0 ad d3 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}