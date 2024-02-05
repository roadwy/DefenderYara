
rule TrojanDropper_Win32_Mariofev_I{
	meta:
		description = "TrojanDropper:Win32/Mariofev.I,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 07 00 08 00 00 02 00 "
		
	strings :
		$a_01_0 = {c7 45 f0 e0 00 00 e0 8d 0c ca } //02 00 
		$a_01_1 = {c7 44 24 44 e0 00 00 e0 8d 04 c1 } //02 00 
		$a_03_2 = {6a 05 50 8d 4d d4 e8 90 01 04 80 7d c0 e9 75 1e 90 00 } //02 00 
		$a_03_3 = {6a 05 50 8d 4c 24 28 e8 90 01 04 80 7c 24 30 e9 75 2c 90 00 } //05 00 
		$a_01_4 = {26 44 69 73 61 62 6c 65 53 66 63 3d 25 64 2d 25 64 } //05 00 
		$a_01_5 = {26 50 61 74 63 68 46 69 6c 65 3d 25 64 2d 25 64 } //01 00 
		$a_01_6 = {64 6c 6c 63 61 63 68 65 5c 6f 6c 65 33 32 2e 64 6c 6c } //01 00 
		$a_01_7 = {44 45 50 41 43 4b 45 4e 44 } //00 00 
	condition:
		any of ($a_*)
 
}