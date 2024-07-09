
rule TrojanSpy_Win32_Hitpop_gen_D{
	meta:
		description = "TrojanSpy:Win32/Hitpop.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b ca d1 f9 79 03 83 d1 00 03 ca 51 8b 55 ?? 8b 45 ?? 2b d0 d1 fa 79 03 83 d2 00 03 d0 52 e8 ?? ?? ff ff } //1
		$a_03_1 = {d1 f8 79 03 83 d0 00 03 45 ?? 50 8b 45 ?? 8b 7d ?? 2b c7 d1 f8 79 03 83 d0 00 03 c7 50 e8 ?? ?? ff ff } //1
		$a_03_2 = {68 01 02 00 00 56 e8 ?? ?? ff ff 6a 00 6a 00 68 02 02 00 00 56 e8 ?? ?? ff ff } //3
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*3) >=4
 
}