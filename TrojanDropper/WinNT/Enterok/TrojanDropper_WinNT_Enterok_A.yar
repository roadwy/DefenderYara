
rule TrojanDropper_WinNT_Enterok_A{
	meta:
		description = "TrojanDropper:WinNT/Enterok.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {c7 00 1f 00 00 00 8b 01 03 c2 0f b6 50 03 56 0f b6 70 02 c1 e2 08 03 d6 0f b6 70 01 0f b6 00 c1 e2 08 03 d6 c1 e2 08 03 d0 8b 45 08 89 10 83 01 04 8b 00 c1 e8 1f } //1
		$a_03_1 = {8a 02 8b 4d ?? 88 04 19 43 42 4e 75 ?? e9 ?? ?? ?? ?? 8b 45 ?? 85 c0 74 ?? 89 18 33 c0 40 } //1
		$a_03_2 = {6a 06 8d 04 37 50 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 83 c4 0c 85 c0 74 ?? 46 81 fe 00 10 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}