
rule PWS_Win32_Lolyda_AG{
	meta:
		description = "PWS:Win32/Lolyda.AG,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_02_0 = {66 6f 6e 74 73 5c 67 74 68 90 0f 05 00 2e 66 6f 6e 90 00 } //01 00 
		$a_00_1 = {73 79 73 67 74 68 2e 64 6c 6c } //01 00  sysgth.dll
		$a_00_2 = {6d 6d 73 66 63 31 2e 64 6c 6c } //02 00  mmsfc1.dll
		$a_03_3 = {85 f6 74 34 2b c3 90 01 30 eb c6 90 00 } //02 00 
		$a_03_4 = {b9 89 02 00 00 33 c0 8d bd 90 01 02 ff ff f3 ab 90 00 } //02 00 
		$a_03_5 = {8a 14 08 80 ea 90 01 01 88 11 41 4e 75 f4 5e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}