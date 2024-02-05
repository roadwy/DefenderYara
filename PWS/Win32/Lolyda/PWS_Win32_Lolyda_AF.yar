
rule PWS_Win32_Lolyda_AF{
	meta:
		description = "PWS:Win32/Lolyda.AF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 06 e9 2b c6 6a 01 83 e8 05 89 46 01 58 } //01 00 
		$a_03_1 = {4e 75 f4 5e 90 09 09 00 8a 14 90 01 01 80 ea 90 01 01 88 90 00 } //01 00 
		$a_02_2 = {66 6f 6e 74 73 5c 67 74 68 90 0f 05 00 2e 90 03 03 03 66 6f 6e 74 74 66 90 00 } //01 00 
		$a_01_3 = {41 63 63 40 26 23 65 70 40 26 23 74 3a 40 26 23 2a 2f 2a } //00 00 
	condition:
		any of ($a_*)
 
}