
rule Trojan_Win32_Legendmir_MA_MTB{
	meta:
		description = "Trojan:Win32/Legendmir.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 64 4a 9b 75 5e 7f 2c 3b 51 79 2f 35 38 49 c1 b0 0b db a1 bf 8b 99 ba 07 27 8b 4a d6 69 28 4d } //01 00 
		$a_01_1 = {47 91 1b df 6b 57 ac ae b3 f3 a1 c6 1d db ae 41 d5 ec db ab 50 da 72 20 1b 1e 59 75 d0 cf ed f4 } //01 00 
		$a_01_2 = {02 06 c1 7f 02 ca d2 17 d1 a3 1d 26 aa 42 a1 0a e6 f3 39 ab 3d b6 d6 3b 8f 3a 14 58 c6 1d 1d 1d } //00 00 
	condition:
		any of ($a_*)
 
}