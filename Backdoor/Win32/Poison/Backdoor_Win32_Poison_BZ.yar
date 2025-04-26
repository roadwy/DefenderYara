
rule Backdoor_Win32_Poison_BZ{
	meta:
		description = "Backdoor:Win32/Poison.BZ,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {8a 14 01 84 d2 74 0e 80 fa 28 74 09 8a 14 01 80 f2 28 88 14 01 40 4e 75 e7 } //10
		$a_01_1 = {58 5a 47 4f 5a 49 45 08 00 45 5d 5b 5c 08 4a 4d 08 00 5a 5d 46 08 5d 46 4c 4d 00 5a 08 7f 41 46 } //1
		$a_01_2 = {e4 21 e9 3b 06 5a 4d 44 47 e6 4b ec 16 e8 68 00 80 00 00 e9 48 ef 3a aa 00 e8 21 78 06 5a 5b 5a } //1
		$a_01_3 = {a8 2a ac e8 5d 2c a8 1b e8 a1 2e 72 75 77 c8 38 29 c9 25 ab ec d0 a3 f0 a3 d3 00 a3 1a a3 6b 20 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=11
 
}