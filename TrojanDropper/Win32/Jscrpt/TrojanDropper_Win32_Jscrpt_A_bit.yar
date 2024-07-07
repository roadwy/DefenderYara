
rule TrojanDropper_Win32_Jscrpt_A_bit{
	meta:
		description = "TrojanDropper:Win32/Jscrpt.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {89 4b 08 89 4d fc 89 4b 0c 51 c6 45 fc 01 51 c7 43 04 01 00 00 00 ff 15 90 01 03 00 c7 45 90 01 05 33 c9 c7 45 90 01 05 6a 90 01 01 58 d3 f8 30 44 0d 90 01 01 41 83 f9 07 72 f1 90 00 } //1
		$a_01_1 = {8b d7 d3 ea 83 c1 08 88 14 18 40 83 f9 20 72 f0 8b 7d f8 85 ff 74 13 8b 4d f4 8b c6 83 e0 03 8a 04 18 30 04 0e 46 3b f7 72 f0 } //2
		$a_03_2 = {8b 06 8b 08 8a 82 90 01 03 00 88 04 0a 42 8b 06 3b 50 04 72 eb 8b 0e 8b 51 04 8b 09 4a e8 90 01 03 00 90 00 } //1
		$a_03_3 = {56 8b d8 53 6a ff ff 37 33 ff 57 57 ff 15 90 01 03 00 8b 75 90 01 01 57 57 6a 02 8b 4e 0c 57 57 57 8b 11 57 68 90 01 03 00 53 51 ff 52 14 8b 46 08 6a 02 50 8b 08 ff 51 14 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=5
 
}