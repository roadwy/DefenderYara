
rule TrojanSpy_Win32_Treemz_gen_A{
	meta:
		description = "TrojanSpy:Win32/Treemz.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 "
		
	strings :
		$a_03_0 = {84 d2 74 0f 8b c8 80 f2 ?? 88 11 8a 51 01 41 84 d2 75 f3 } //1
		$a_03_1 = {8a 51 01 41 84 d2 75 ?? 5d c3 90 09 03 00 80 31 } //1
		$a_03_2 = {85 c0 7e 09 80 34 31 ?? 41 3b c8 7c f7 } //1
		$a_03_3 = {7e 0c 80 34 1f ?? 53 47 ff d6 3b f8 7c f4 } //1
		$a_03_4 = {8d 45 f8 c6 45 f8 e9 50 56 68 ?? ?? ?? ?? 88 5d f9 88 5d fa 88 5d fb 88 5d fc } //2
		$a_03_5 = {57 50 6a 02 ff 15 ?? ?? ?? ?? 85 c0 75 (5b|57) ff 75 08 ff 15 ?? ?? ?? ?? 6a 00 6a 01 6a 02 8b f0 ff 15 } //2
		$a_03_6 = {03 ce 8a 84 85 f4 fb ff ff 30 01 46 81 fe 80 00 00 00 (72|7c) } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*2+(#a_03_5  & 1)*2+(#a_03_6  & 1)*2) >=3
 
}