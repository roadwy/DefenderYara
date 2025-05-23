
rule TrojanSpy_Win32_Ursnif_gen_P{
	meta:
		description = "TrojanSpy:Win32/Ursnif.gen!P,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 0b 00 00 "
		
	strings :
		$a_01_0 = {33 55 f8 43 33 d0 8a cb d3 ca } //1
		$a_01_1 = {80 39 36 75 04 8b c1 eb 09 c6 00 36 c6 40 01 34 } //1
		$a_01_2 = {66 3d 4a 31 74 17 0f b7 46 14 83 c6 14 66 85 c0 75 ee } //1
		$a_01_3 = {8b 31 8d 51 08 8b 0a 83 c1 01 81 e1 fe 00 00 00 ff 34 ca e2 fb } //1
		$a_01_4 = {6a d4 58 2b 45 fc 03 f0 33 c0 85 c9 74 09 8d 46 fc 3b c6 76 02 33 c0 83 fe 04 76 03 6a 04 5e } //1
		$a_01_5 = {0f b7 46 04 b9 64 86 00 00 8b d1 66 3b c2 8b 46 28 } //1
		$a_03_6 = {6b c9 28 03 c8 8d 74 0a 40 eb 0d b9 ?? ?? ?? ?? 66 3b c1 74 0d } //1
		$a_01_7 = {0f be 0c 07 03 4d f4 81 f1 fc 58 85 cf 01 4d f8 40 3b c6 72 eb } //1
		$a_01_8 = {c6 06 68 89 5e 01 c6 46 05 e8 c7 46 06 12 01 00 00 c6 46 0a be 89 7e 0b c6 46 11 c2 } //1
		$a_01_9 = {3d 04 df 22 09 74 15 3d 39 9d 2d 66 74 0e 3d f0 40 4f c8 74 07 3d ff a3 75 3d 75 0b } //1
		$a_01_10 = {ff 45 f8 33 d1 8a 4d f8 33 d6 d3 ca 8b 4d ec 89 17 83 c7 04 ff 4d f4 75 de } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=3
 
}