
rule PWS_Win32_Yaludle_A{
	meta:
		description = "PWS:Win32/Yaludle.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 11 50 46 e8 ?? ?? ff ff 88 07 8a 06 47 (59 84 c0|84 c0 59) 75 ef 80 27 00 5f 5e c3 } //1
		$a_03_1 = {55 8b ec 83 ec 50 56 57 6a 13 [0-10] f3 a5 [0-10] 66 a5 [0-0c] 50 a4 e8 ba ff ff ff [0-05] 59 [0-05] 5e 74 14 8d 4d b0 [0-07] 2b c1 [0-07] 83 c0 27 [0-05] f7 f9 8a 44 15 b0 c9 c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}