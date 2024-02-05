
rule Worm_Win32_Koobface_gen_B{
	meta:
		description = "Worm:Win32/Koobface.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 54 41 25 73 43 45 00 52 54 4f 4e 90 02 10 25 73 5c 74 74 5f 25 64 2e 65 78 65 00 90 00 } //01 00 
		$a_01_1 = {26 76 3d 25 73 26 63 3d 25 64 26 73 3d 25 73 26 6c 3d 25 73 } //01 00 
		$a_01_2 = {41 43 48 5f 4f 4b 00 } //01 00 
		$a_01_3 = {2f 67 65 6e 2e 70 68 70 00 } //01 00 
		$a_01_4 = {36 46 31 33 7d 22 0a 22 45 78 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}