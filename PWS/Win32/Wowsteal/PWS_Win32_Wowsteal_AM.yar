
rule PWS_Win32_Wowsteal_AM{
	meta:
		description = "PWS:Win32/Wowsteal.AM,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {26 75 3d 25 73 26 70 3d 25 73 26 70 69 6e 3d 25 73 26 72 3d 25 73 } //01 00 
		$a_01_1 = {25 73 3f 75 73 65 72 3d 25 73 26 70 61 73 73 3d 25 73 26 6a 75 6d 69 6e 31 3d 25 73 26 6a 75 6d 69 6e 32 3d 25 73 26 6e 61 6d 65 3d 25 73 } //02 00 
		$a_01_2 = {8a 18 32 da 88 18 40 49 75 f6 5b } //02 00 
		$a_01_3 = {81 fe 96 00 00 00 7e 35 81 fe e8 03 00 00 7d 2d } //00 00 
	condition:
		any of ($a_*)
 
}