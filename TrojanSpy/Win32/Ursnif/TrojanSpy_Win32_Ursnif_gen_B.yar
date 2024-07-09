
rule TrojanSpy_Win32_Ursnif_gen_B{
	meta:
		description = "TrojanSpy:Win32/Ursnif.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b 07 8b c8 74 ?? 85 c0 75 ?? 33 d2 42 eb ?? 33 c3 33 45 ?? 83 c7 04 ff 45 ?? 8b d9 8a 4d ?? d3 c8 89 06 83 c6 04 4a 75 } //2
		$a_00_1 = {2e 62 73 73 00 00 00 00 22 25 53 22 } //1
		$a_03_2 = {3d 70 6e 6c 73 75 ?? ff 73 ?? 03 d6 57 52 e8 } //1
		$a_01_3 = {8b 47 3c 03 c7 0f b7 50 06 0f b7 70 14 6b d2 28 81 f1 3a 24 00 00 0f b7 c9 03 d0 } //1
		$a_03_4 = {c6 04 03 00 83 7e 10 04 72 ?? 8b 46 ?? 31 03 8b 45 ?? 8b 4d ?? 89 18 8b 46 10 89 01 8b 44 24 10 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=10
 
}