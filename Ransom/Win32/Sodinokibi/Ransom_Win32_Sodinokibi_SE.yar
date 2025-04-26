
rule Ransom_Win32_Sodinokibi_SE{
	meta:
		description = "Ransom:Win32/Sodinokibi.SE,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0a 00 00 "
		
	strings :
		$a_03_0 = {33 4f 1c 83 c7 20 d1 f8 83 e8 01 89 45 0c e9 ?? ?? ?? ?? 8b 75 10 } //1
		$a_03_1 = {8b 7d 08 8d b5 68 ff ff ff 83 c4 14 90 0a 0e 00 50 e8 } //1
		$a_01_2 = {83 e8 01 eb 07 b0 0a 5d c3 83 e8 62 74 28 } //1
		$a_01_3 = {8d 85 10 ff ff ff 50 8d 85 60 ff ff ff 50 8d 45 b0 50 e8 } //1
		$a_01_4 = {ff 75 0c 8d 45 b0 50 8d 85 c0 fe ff ff 50 } //1
		$a_01_5 = {8b 45 08 8b 40 4c 89 45 f0 8b 45 e8 89 4b 28 f7 d0 23 c2 } //1
		$a_01_6 = {33 4d e0 8b 40 48 8b 5d 08 89 45 ec 8b 45 08 } //1
		$a_03_7 = {ff 75 20 e8 ?? ?? ?? ?? 8d 85 80 fe ff ff 50 ff 75 24 } //1
		$a_01_8 = {89 75 d8 0f b6 45 ff 0b c8 8b c1 89 4d d8 } //1
		$a_01_9 = {83 e8 13 0f 84 61 06 00 00 83 e8 3d 0f 84 fa 02 00 00 f6 c2 04 74 11 80 f9 2c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_03_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=7
 
}