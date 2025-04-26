
rule TrojanDropper_Win32_Nebuler_D{
	meta:
		description = "TrojanDropper:Win32/Nebuler.D,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e4 83 c0 01 89 45 e4 90 09 07 00 88 94 05 } //1
		$a_03_1 = {8b 55 e4 83 c2 01 89 55 e4 90 09 07 00 88 8c 15 } //1
		$a_03_2 = {8b 4d e4 83 c1 01 89 4d e4 90 09 07 00 88 84 0d } //1
		$a_03_3 = {2a cb 80 14 75 0f 90 09 06 00 81 bd } //4
		$a_03_4 = {71 fe ff 8b ?? ?? ?? ?? ff 0f b6 ?? 00 60 40 00 33 ?? 8b } //4
		$a_03_5 = {8b 51 08 ff d2 89 45 ?? 8b 45 08 05 ?? ?? ?? ?? 50 8b 4d ?? 51 8b 55 08 8b 42 04 ff d0 } //4
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*4+(#a_03_4  & 1)*4+(#a_03_5  & 1)*4) >=9
 
}