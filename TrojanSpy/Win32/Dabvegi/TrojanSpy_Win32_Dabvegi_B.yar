
rule TrojanSpy_Win32_Dabvegi_B{
	meta:
		description = "TrojanSpy:Win32/Dabvegi.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 45 10 66 8b 4d ?? 33 d2 66 3b 08 0f 94 c2 f7 da } //1
		$a_01_1 = {8d 8e f8 00 00 00 89 46 5c 89 41 0c c7 01 53 5a 44 44 c7 41 04 88 f0 27 33 66 c7 41 08 41 00 } //1
		$a_03_2 = {8d 47 fe 83 f8 04 0f 87 f9 00 00 00 ff 24 85 ?? ?? ?? ?? 8d 4d ?? 8d 55 ?? 51 8b 0d ?? ?? ?? ?? 8d 45 ?? 52 89 75 ?? c7 45 ?? 05 00 00 00 c7 45 ?? 01 00 00 00 } //1
		$a_03_3 = {80 e1 7f 66 0f b6 c9 66 6b c9 02 0f 80 ?? ?? ?? ?? (34 1b|80 f2 1b) 66 33 ?? 8a ?? 33 ?? eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}