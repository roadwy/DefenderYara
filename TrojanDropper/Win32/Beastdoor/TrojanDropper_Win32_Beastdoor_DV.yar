
rule TrojanDropper_Win32_Beastdoor_DV{
	meta:
		description = "TrojanDropper:Win32/Beastdoor.DV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 10 01 00 00 68 ?? ?? 40 00 a1 ?? ?? 40 00 50 ff 15 ?? ?? 40 00 ba 05 01 00 00 b8 ?? ?? 40 00 8a 08 32 0b 88 08 40 4a 75 f6 33 c0 8a 03 31 05 ?? ?? 40 00 31 05 ?? ?? 40 00 5b } //1
		$a_01_1 = {8b 55 f8 85 d2 72 11 42 33 c0 33 c9 8a 0c 03 33 ce 88 0c 03 40 4a 75 f2 46 81 fe c9 00 00 00 75 df 8b 55 f8 85 d2 72 13 42 33 c0 8a 0c 03 } //1
		$a_03_2 = {40 00 33 c0 a0 ?? ?? 40 00 31 05 ?? ?? 40 00 e8 ?? ?? ff ff 8d 45 c4 ba ?? ?? 40 00 b9 05 01 00 00 e8 ?? ?? ff ff 8b 45 c4 8b 0d ?? ?? 40 00 8b 15 ?? ?? 40 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}