
rule Ransom_Win32_Sodinokibi_SC{
	meta:
		description = "Ransom:Win32/Sodinokibi.SC,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_03_0 = {59 85 f6 74 25 8b 55 08 83 66 04 00 89 3e 8b 0a 0b 4a 04 90 0a 14 00 59 } //1
		$a_01_1 = {8d 45 f8 89 75 fc 50 8d 45 fc 89 75 f8 50 56 56 6a 01 6a 30 } //1
		$a_01_2 = {75 0c 72 d3 33 c0 40 5f 5e 5b 8b e5 5d c3 33 c0 eb f5 55 8b ec 83 } //1
		$a_01_3 = {0c 8b 04 b0 83 78 04 05 75 1c ff 70 08 ff 70 0c ff 75 0c ff } //1
		$a_01_4 = {fb 8b 45 fc 50 8b 08 ff 51 08 5e 8b c7 5f 5b 8b e5 5d c3 55 } //1
		$a_03_5 = {33 d2 8b 4d f4 8b f1 8b 45 f0 0f a4 c1 01 c1 ee 1f 90 0a 15 00 bc 00 00 00 } //1
		$a_01_6 = {54 8b ce f7 d1 8b c2 23 4d dc f7 d0 33 4d f4 23 c7 33 45 e8 89 } //1
		$a_01_7 = {0c 89 46 0c 85 c0 75 2a 33 c0 eb 6c 8b 46 08 85 c0 74 62 6b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=6
 
}