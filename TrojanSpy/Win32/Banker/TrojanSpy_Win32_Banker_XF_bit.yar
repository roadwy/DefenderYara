
rule TrojanSpy_Win32_Banker_XF_bit{
	meta:
		description = "TrojanSpy:Win32/Banker.XF!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 0c 06 88 08 8b 4d fc 42 40 3b d1 72 f2 } //1
		$a_01_1 = {8a 14 07 88 10 41 40 3b 4d fc 72 f4 } //1
		$a_03_2 = {8b f1 c1 ee ?? 03 35 ?? ?? ?? ?? 8b f9 c1 e7 ?? 03 3d ?? ?? ?? ?? 33 f7 8d 3c 0a 33 f7 2b c6 8b f0 c1 ee ?? 03 35 ?? ?? ?? ?? 8b f8 c1 e7 ?? 03 3d ?? ?? ?? ?? 33 f7 8d 3c 02 33 f7 2b ce } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2) >=3
 
}