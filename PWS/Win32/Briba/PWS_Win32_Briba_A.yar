
rule PWS_Win32_Briba_A{
	meta:
		description = "PWS:Win32/Briba.A,SIGNATURE_TYPE_PEHSTR_EXT,10 00 0f 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {63 30 64 30 73 6f 30 } //01 00 
		$a_00_1 = {4d 53 4d 41 50 49 33 32 2e 53 52 47 } //01 00 
		$a_03_2 = {50 4f 53 54 90 02 10 69 6e 64 65 78 25 30 2e 39 64 2e 61 73 70 90 00 } //02 00 
		$a_01_3 = {2b c2 d1 e8 03 c2 c1 e8 1d 69 c0 00 ca 9a 3b } //02 00 
		$a_01_4 = {80 f9 3a 74 0f 80 f9 20 74 0a 40 3b c7 } //00 00 
		$a_00_5 = {5d 04 00 00 43 b3 02 80 5c 2d 00 00 } //48 b3 
	condition:
		any of ($a_*)
 
}