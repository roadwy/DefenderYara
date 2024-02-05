
rule Trojan_Win32_Emotet_ADC_MTB{
	meta:
		description = "Trojan:Win32/Emotet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffff83 00 ffffff83 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //0a 00 
		$a_03_1 = {55 8b ec 83 e4 f8 81 ec a0 00 00 00 53 55 56 c7 44 24 90 01 05 be 90 01 04 8b 5c 24 90 01 01 bd 90 01 04 57 8b 7c 24 90 01 01 c7 44 24 90 00 } //0a 00 
		$a_03_2 = {8b f0 f7 de 1b f6 81 e6 90 01 04 81 c6 90 01 04 e9 90 00 } //0a 00 
		$a_01_3 = {83 c4 14 6a 00 ff d0 8b e5 5d 90 00 } //32 00 
		$a_03_4 = {53 57 8b f8 8b cd d3 e7 8b d8 8b 4c 24 90 01 01 d3 e0 8b c8 66 83 fa 41 72 90 01 01 66 83 fa 5a 77 90 00 } //32 00 
		$a_03_5 = {0f b7 c2 83 c0 20 eb 90 01 01 0f b7 c2 83 c6 02 2b cb 03 cf 03 c1 0f b7 16 66 85 d2 75 90 01 01 5f 5b 5e 5d 59 59 90 00 } //00 00 
		$a_00_6 = {5d 04 00 00 02 13 05 80 5c 2b 00 00 03 13 05 80 00 00 01 00 08 00 15 00 af 01 41 67 65 6e 74 54 65 73 6c 61 2e 52 50 58 4d 21 4d 54 42 00 00 01 40 05 82 70 00 04 00 e7 59 00 00 00 00 55 00 17 3f fc 73 bc f2 ea 8f e6 80 bc c2 f2 d1 80 d0 80 8f e6 80 bc c2 bc d1 ea 0b c2 99 f2 1e c2 d1 80 1e 8f e6 80 bc c2 3f d0 c2 99 f2 1e c2 d1 80 1e 8f a3 c7 0f 93 ec ad c7 17 e7 78 e3 3e 80 3f 1e 0f 80 } //d1 ea 
	condition:
		any of ($a_*)
 
}