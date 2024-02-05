
rule Worm_Win32_Yeltminky_A{
	meta:
		description = "Worm:Win32/Yeltminky.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 db 8a 1c 10 66 81 f3 90 01 02 88 1c 11 42 4e 75 ef 90 00 } //01 00 
		$a_03_1 = {74 11 6a 00 6a 03 6a 00 a1 90 01 04 50 e8 90 01 04 80 3d 90 01 04 00 74 11 6a 00 6a 02 6a 00 a1 90 01 04 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}