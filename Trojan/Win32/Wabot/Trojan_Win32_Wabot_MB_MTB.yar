
rule Trojan_Win32_Wabot_MB_MTB{
	meta:
		description = "Trojan:Win32/Wabot.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {7d fa 13 27 e0 94 d7 c0 e0 42 f8 91 3f 8e a1 6b 94 b3 11 d2 df 6b 68 92 91 16 0c 0b 4b 56 6d 8b } //1
		$a_01_1 = {c6 97 55 3a ab 26 13 6c 4b c8 25 5d 81 02 35 a2 29 70 95 eb f7 e3 7f c9 a7 2f c8 9a b7 d5 de db } //1
		$a_01_2 = {35 f0 21 6f 57 18 05 ac d8 27 8b 2a 57 04 f5 ba 34 e7 d0 f6 aa c4 a4 4a 1b bf 02 74 d3 e1 a7 d3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}