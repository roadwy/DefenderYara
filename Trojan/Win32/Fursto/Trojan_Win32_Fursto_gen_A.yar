
rule Trojan_Win32_Fursto_gen_A{
	meta:
		description = "Trojan:Win32/Fursto.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,23 00 19 00 09 00 00 "
		
	strings :
		$a_01_0 = {b6 ba b9 96 93 8b 9a 8d d1 9b 93 93 00 } //10
		$a_01_1 = {b2 ac b6 ba b7 9a 93 8f 9a 8d d1 9b 93 93 00 } //10
		$a_01_2 = {ac 90 99 8b 88 9e 8d 9a a3 a3 b2 96 9c 8d 90 8c 90 99 8b a3 a3 b9 96 93 8b 9a 8d 00 } //10
		$a_01_3 = {ac 90 99 8b 88 9e 8d 9a a3 b2 96 9c 8d 90 8c 90 99 8b a3 b9 96 93 8b 9a 8d 00 } //10
		$a_01_4 = {b1 9a 9a 9b ac 9a 91 9b b6 91 99 } //10
		$a_00_5 = {74 0c f6 d0 88 03 8a 43 01 43 84 c0 75 f4 } //5
		$a_00_6 = {74 0a f6 d0 88 07 8a 47 01 47 eb f2 } //5
		$a_00_7 = {74 18 8b 4d fc 0f be 11 f7 d2 8b 45 fc 88 10 8b 4d fc 83 c1 01 89 4d fc eb de } //5
		$a_00_8 = {74 18 8b 45 fc 0f be 08 f7 d1 8b 55 fc 88 0a 8b 45 fc 83 c0 01 89 45 fc eb de } //5
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_00_5  & 1)*5+(#a_00_6  & 1)*5+(#a_00_7  & 1)*5+(#a_00_8  & 1)*5) >=25
 
}