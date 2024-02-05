
rule Worm_Win32_Phdet_A{
	meta:
		description = "Worm:Win32/Phdet.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 24 0e 48 9c 90 09 05 00 6a 5a 90 01 01 ff d0 90 00 } //01 00 
		$a_01_1 = {69 64 3d 25 73 26 6c 6e 3d 25 73 26 63 6e 3d 25 73 26 6e 74 3d 25 73 } //01 00 
		$a_01_2 = {4c 64 72 50 72 6f 63 22 20 26 20 56 62 43 72 4c 66 } //00 00 
	condition:
		any of ($a_*)
 
}