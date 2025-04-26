
rule Worm_Win32_Gamarue_AP{
	meta:
		description = "Worm:Win32/Gamarue.AP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {33 c0 eb 0b 0f be c9 33 c8 c1 c1 0a 8b c1 42 8a 0a 84 c9 75 ef 35 3e c7 a6 13 c3 } //1
		$a_01_1 = {8b 4d fc 8b 55 dc 8b 75 e4 03 ca 89 0e 8b 4d fc 8d 3c 0a 8b c8 03 d0 8b f3 f3 a4 8b 4d fc c6 04 0a e9 8b 4d fc 2b c2 2b c1 8d 44 18 fb 8b 5d e4 89 44 0a 01 83 c2 05 89 55 dc eb 03 } //1
		$a_01_2 = {ac 8a c8 3c 0f 74 0f 66 81 7e ff cd 20 75 0a 46 ad } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}