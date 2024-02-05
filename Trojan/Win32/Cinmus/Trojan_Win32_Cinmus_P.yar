
rule Trojan_Win32_Cinmus_P{
	meta:
		description = "Trojan:Win32/Cinmus.P,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {64 6f 73 73 73 65 74 75 70 2e 64 6c 6c } //01 00 
		$a_00_1 = {76 65 72 3d 25 73 2c 66 69 64 3d 25 73 2c 66 69 6c 65 3d 25 73 2c 6e 41 63 74 69 6f 6e 3d 25 64 00 } //01 00 
		$a_01_2 = {5c 5c 2e 5c 70 69 70 65 5c 44 46 46 41 46 31 42 46 43 34 34 62 30 31 42 41 31 44 31 38 31 38 36 42 37 46 31 37 33 33 00 } //01 00 
		$a_01_3 = {72 03 73 01 e8 } //00 00 
	condition:
		any of ($a_*)
 
}