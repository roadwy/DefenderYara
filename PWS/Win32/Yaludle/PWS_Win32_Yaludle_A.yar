
rule PWS_Win32_Yaludle_A{
	meta:
		description = "PWS:Win32/Yaludle.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {74 11 50 46 e8 90 01 02 ff ff 88 07 8a 06 47 90 03 03 03 59 84 c0 84 c0 59 75 ef 80 27 00 5f 5e c3 90 00 } //01 00 
		$a_03_1 = {55 8b ec 83 ec 50 56 57 6a 13 90 02 10 f3 a5 90 02 10 66 a5 90 02 0c 50 a4 e8 ba ff ff ff 90 02 05 59 90 02 05 5e 74 14 8d 4d b0 90 02 07 2b c1 90 02 07 83 c0 27 90 02 05 f7 f9 8a 44 15 b0 c9 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}