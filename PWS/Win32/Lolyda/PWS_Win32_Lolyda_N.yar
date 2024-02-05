
rule PWS_Win32_Lolyda_N{
	meta:
		description = "PWS:Win32/Lolyda.N,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 90 01 00 00 68 58 02 00 00 6a 64 6a 64 68 00 00 cf 00 } //01 00 
		$a_01_1 = {68 0b e0 22 00 } //01 00 
		$a_00_2 = {48 42 49 6e 6a 65 63 74 33 32 00 } //01 00 
		$a_00_3 = {48 42 4b 65 72 6e 65 6c 33 32 00 } //00 00 
	condition:
		any of ($a_*)
 
}