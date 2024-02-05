
rule PWS_Win32_Yaludle_B{
	meta:
		description = "PWS:Win32/Yaludle.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 1d 56 8b 74 24 0c 50 47 e8 87 ff ff ff 88 06 8a 07 83 c4 04 46 84 c0 75 ed } //01 00 
		$a_01_1 = {c1 4d fc 0d 0f be 01 8b 55 fc 03 d0 8a 41 01 41 84 c0 89 55 fc 75 e9 } //01 00 
		$a_01_2 = {b8 d3 4d 62 10 f7 e2 8b c2 c1 e8 06 33 d2 b9 80 51 01 00 f7 f1 } //00 00 
	condition:
		any of ($a_*)
 
}