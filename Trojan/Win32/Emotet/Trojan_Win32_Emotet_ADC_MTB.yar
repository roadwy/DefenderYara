
rule Trojan_Win32_Emotet_ADC_MTB{
	meta:
		description = "Trojan:Win32/Emotet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffff83 00 ffffff83 00 06 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {55 8b ec 83 e4 f8 81 ec a0 00 00 00 53 55 56 c7 44 24 ?? ?? ?? ?? ?? be ?? ?? ?? ?? 8b 5c 24 ?? bd ?? ?? ?? ?? 57 8b 7c 24 ?? c7 44 24 } //10
		$a_03_2 = {8b f0 f7 de 1b f6 81 e6 ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? e9 } //10
		$a_01_3 = {83 c4 14 6a 00 ff d0 8b e5 5d } //10
		$a_03_4 = {53 57 8b f8 8b cd d3 e7 8b d8 8b 4c 24 ?? d3 e0 8b c8 66 83 fa 41 72 ?? 66 83 fa 5a 77 } //50
		$a_03_5 = {0f b7 c2 83 c0 20 eb ?? 0f b7 c2 83 c6 02 2b cb 03 cf 03 c1 0f b7 16 66 85 d2 75 ?? 5f 5b 5e 5d 59 59 } //50
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10+(#a_01_3  & 1)*10+(#a_03_4  & 1)*50+(#a_03_5  & 1)*50) >=131
 
}