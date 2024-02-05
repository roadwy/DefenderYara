
rule PWS_Win32_Dipwit_A{
	meta:
		description = "PWS:Win32/Dipwit.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 26 69 70 3d ab e8 } //01 00 
		$a_01_1 = {8b 40 02 8b 00 ab 66 b8 ff d0 66 ab 66 b8 85 c0 66 ab 66 b8 75 f0 } //02 00 
		$a_01_2 = {81 7d 50 57 65 62 4d 75 42 81 7d 58 20 4b 65 65 75 39 81 7d 60 43 6c 61 73 } //02 00 
		$a_01_3 = {ad 33 c2 d3 c2 ab e2 f8 5f 51 6a 06 6a 02 51 51 } //00 00 
	condition:
		any of ($a_*)
 
}