
rule PWS_Win32_Lolyda_BC{
	meta:
		description = "PWS:Win32/Lolyda.BC,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {29 26 85 d9 ed 93 e1 33 6e be 01 b6 03 14 d8 f8 } //01 00 
		$a_01_1 = {32 d0 88 14 31 8a c2 8a 14 1f 2a c2 47 83 ff 04 88 04 31 72 02 33 ff 41 3b cd 72 de } //01 00 
		$a_03_2 = {6a 04 83 ea 05 90 01 02 89 56 01 90 00 } //01 00 
		$a_01_3 = {6d 69 62 61 6f 2e 61 73 70 3f 61 63 74 3d 26 } //00 00 
	condition:
		any of ($a_*)
 
}