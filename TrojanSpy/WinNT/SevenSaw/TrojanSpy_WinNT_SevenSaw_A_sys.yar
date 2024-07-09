
rule TrojanSpy_WinNT_SevenSaw_A_sys{
	meta:
		description = "TrojanSpy:WinNT/SevenSaw.A!sys,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_02_0 = {68 9e 00 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 43 60 83 e8 24 89 70 1c 8b 74 24 10 68 ?? ?? ?? ?? 89 70 20 c6 40 03 e0 } //1
		$a_00_1 = {8b 45 fc 66 81 48 1c 04 20 8b 45 fc 80 60 1c 7f 53 } //1
		$a_02_2 = {68 44 64 6b 20 6a 0c 6a 00 c6 46 18 00 ff 15 ?? ?? ?? ?? 8b e8 8a 47 fe 88 45 08 8a 07 } //1
		$a_02_3 = {57 33 c0 50 b8 40 42 0f 00 50 8d 45 d0 50 ff 15 ?? ?? ?? ?? 57 57 57 57 8d 45 d0 50 ff d3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=3
 
}