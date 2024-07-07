
rule TrojanDropper_Win32_Nuwar_gen_A{
	meta:
		description = "TrojanDropper:Win32/Nuwar.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_00_0 = {47 0f b7 45 fc 33 d2 f7 f7 30 14 33 43 47 3b d9 72 ef ff 75 f4 56 ff 75 f8 } //1
		$a_00_1 = {56 8d 85 cc fc ff ff 50 e8 cf 01 00 00 83 c4 0c a1 40 20 40 00 89 85 cc fc ff ff 83 8d e0 fc ff ff 01 81 a5 e0 fc ff ff ff ff f0 ff } //1
		$a_02_2 = {81 e0 ff 00 00 00 8b 4d f8 0f b6 09 31 c1 8b 45 f8 88 08 eb 90 01 01 c9 c3 90 00 } //1
		$a_02_3 = {81 e0 ff 00 00 00 88 45 90 01 01 8b 45 08 8b 4d fc 01 c8 0f b6 4d 90 01 01 0f b6 55 90 01 01 31 d1 88 08 eb 90 01 01 c9 c3 90 00 } //1
		$a_02_4 = {81 e0 ff 00 00 00 90 02 03 88 45 90 01 01 8b 45 08 8b 4d fc 01 c8 0f b6 4d 90 01 01 51 0f b6 4d 90 01 01 51 89 45 90 02 40 88 01 90 03 04 04 eb 90 01 01 e9 90 01 04 c9 c3 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1) >=1
 
}