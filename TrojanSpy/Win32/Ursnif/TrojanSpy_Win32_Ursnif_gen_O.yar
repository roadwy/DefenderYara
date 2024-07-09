
rule TrojanSpy_Win32_Ursnif_gen_O{
	meta:
		description = "TrojanSpy:Win32/Ursnif.gen!O,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {0f be 08 83 f9 21 75 6a 6a 01 6a 00 8d 4d c4 e8 } //2
		$a_03_1 = {68 d9 13 00 00 68 ?? ?? ?? ?? 6a 01 a1 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? e8 } //2
		$a_01_2 = {8b 45 fc 03 45 f8 0f be 08 33 d1 8b 45 f4 03 45 f0 88 10 } //2
		$a_01_3 = {5b 62 6f 74 5d 0a 0a 69 64 3d 00 } //1
		$a_01_4 = {5b 72 65 71 75 65 73 74 5d 0a 74 79 70 65 3d 61 73 6b 5f 63 61 6d 70 61 69 67 6e 0a 0a 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}