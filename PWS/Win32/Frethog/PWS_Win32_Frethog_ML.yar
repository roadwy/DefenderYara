
rule PWS_Win32_Frethog_ML{
	meta:
		description = "PWS:Win32/Frethog.ML,SIGNATURE_TYPE_PEHSTR_EXT,04 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {c1 eb 02 8b 4d 14 33 d2 8b 04 96 41 83 e1 1f d3 c0 33 c7 90 89 04 96 42 3b d3 75 ec 61 5f 5e 5b } //01 00 
		$a_03_1 = {8b c8 31 11 83 c1 04 81 f9 90 01 04 72 f3 53 56 57 6a 01 68 12 f8 33 c6 90 00 } //01 00 
		$a_01_2 = {8a d1 32 d0 3a cb 88 17 74 05 40 3b c6 72 e5 33 c0 8a } //00 00 
	condition:
		any of ($a_*)
 
}