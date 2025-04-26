
rule TrojanDropper_Win32_Tilcun_B{
	meta:
		description = "TrojanDropper:Win32/Tilcun.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b cf 0f b6 45 ff 2b c8 6a 00 83 e9 07 6a 00 51 ff 75 f8 ff d3 8d 45 f4 6a 00 50 8d 85 ?? ?? ff ff 6a 06 50 ff 75 f8 ff 15 ?? ?? 40 00 33 c0 80 b4 05 ?? ?? ff ff ?? 40 83 f8 06 7c f2 } //3
		$a_00_1 = {5c 77 69 6e 73 79 73 2e 72 65 67 00 } //1
		$a_01_2 = {5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 00 } //1
		$a_01_3 = {68 21 74 9e 22 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}