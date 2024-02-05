
rule Backdoor_Win32_Haxdoor_gen_B{
	meta:
		description = "Backdoor:Win32/Haxdoor.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 08 00 00 02 00 "
		
	strings :
		$a_03_0 = {40 ff d0 6a 00 90 09 08 00 b8 90 01 04 83 c0 90 00 } //02 00 
		$a_03_1 = {50 83 2c 24 90 01 01 ff 0c 24 c3 90 09 05 00 b8 90 00 } //02 00 
		$a_01_2 = {7f 0b 83 c7 04 8b 0f 0b c9 75 ee eb 44 8b d8 8d 45 08 6a 04 50 53 e8 } //02 00 
		$a_01_3 = {c6 01 e9 2b c1 83 e8 05 89 41 01 } //02 00 
		$a_01_4 = {66 3d 21 21 75 19 57 8b f9 b9 e8 03 00 00 b0 3c f2 ae 81 7f ff 3c 21 21 3e } //01 00 
		$a_01_5 = {c7 00 5b 53 4f 4c } //01 00 
		$a_01_6 = {c7 00 5b 43 45 52 } //03 00 
		$a_03_7 = {d1 ef 6a 18 56 e8 90 01 04 83 c6 18 4f 75 f2 ff 35 90 01 04 81 2c 24 90 01 04 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}