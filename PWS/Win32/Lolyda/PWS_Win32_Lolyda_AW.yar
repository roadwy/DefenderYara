
rule PWS_Win32_Lolyda_AW{
	meta:
		description = "PWS:Win32/Lolyda.AW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {78 38 42 ec 00 53 65 74 57 69 6e 64 6f 77 00 } //01 00 
		$a_00_1 = {73 73 31 32 44 30 30 30 64 6c 6c 2e 64 6c 6c } //01 00 
		$a_01_2 = {75 1f 8b 7d fc 8b 55 08 8b df 2b d3 83 ea 05 89 55 f8 b0 e9 aa 8d 75 f8 b9 04 00 00 00 f3 a4 } //01 00 
		$a_01_3 = {eb 08 eb 06 aa e9 } //00 00 
	condition:
		any of ($a_*)
 
}