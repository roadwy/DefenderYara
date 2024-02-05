
rule Worm_Win32_Playnro_A{
	meta:
		description = "Worm:Win32/Playnro.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {63 6d 64 00 90 02 10 6f 70 65 6e 00 90 02 20 77 69 6e 6c 67 6e 90 02 05 65 78 65 90 00 } //01 00 
		$a_03_1 = {63 6f 70 79 90 02 20 2f 63 20 61 74 74 72 69 62 20 2d 68 20 2d 73 90 00 } //01 00 
		$a_01_2 = {73 74 61 72 74 20 6e 65 77 20 67 61 6d 65 } //01 00 
		$a_01_3 = {00 5c 4d 79 52 00 } //00 00 
		$a_00_4 = {5d 04 00 00 7b } //3b 03 
	condition:
		any of ($a_*)
 
}