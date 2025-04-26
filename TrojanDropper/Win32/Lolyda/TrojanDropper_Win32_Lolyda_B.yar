
rule TrojanDropper_Win32_Lolyda_B{
	meta:
		description = "TrojanDropper:Win32/Lolyda.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 1c 30 80 f3 19 88 1c 30 40 3b c1 72 ee } //1
		$a_01_1 = {74 0e 8a 14 01 80 f2 86 88 14 01 40 3b c7 72 f2 } //1
		$a_00_2 = {24 24 24 24 5f 5f 5f 5f 5f 5f 24 24 24 24 } //1 $$$$______$$$$
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}