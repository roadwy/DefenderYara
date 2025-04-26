
rule TrojanSpy_Win32_Hitpop_gen_B{
	meta:
		description = "TrojanSpy:Win32/Hitpop.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {67 67 5f 78 73 00 } //1 杧硟s
		$a_00_1 = {67 67 5f 63 6f 75 6e 74 00 } //1
		$a_00_2 = {67 67 5f 6a 67 00 } //1 杧機g
		$a_00_3 = {64 78 5f 6a 67 00 } //1 硤機g
		$a_00_4 = {70 6d 5f 74 69 6d 65 00 } //1 浰瑟浩e
		$a_00_5 = {70 6d 5f 63 6f 75 6e 74 00 } //1
		$a_03_6 = {eb 25 6a 10 68 90 00 68 90 00 e8 ?? ?? ff ff 83 c0 64 50 68 60 f0 ff ff 6a fe 8b 45 f8 50 e8 } //6
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_03_6  & 1)*6) >=6
 
}