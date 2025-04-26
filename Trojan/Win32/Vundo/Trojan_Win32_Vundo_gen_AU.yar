
rule Trojan_Win32_Vundo_gen_AU{
	meta:
		description = "Trojan:Win32/Vundo.gen!AU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_03_0 = {76 10 8b 55 08 0f be 02 83 f0 ?? 8b 4d 08 88 01 eb d8 } //2
		$a_03_1 = {75 76 8b 4d 0c 0f b7 71 02 6a 50 e8 ?? ?? ?? ?? 0f b7 d0 3b f2 } //2
		$a_01_2 = {76 6d 63 5f 6d 65 73 73 61 67 65 00 } //1 浶彣敭獳条e
		$a_01_3 = {00 25 73 5f 5f 63 30 30 25 58 2e } //1
		$a_01_4 = {25 73 3f 61 3d 25 73 26 74 3d 25 73 } //1 %s?a=%s&t=%s
		$a_01_5 = {83 f8 50 74 0b 3d b7 00 00 00 0f 85 b9 00 00 00 ff 45 f8 81 7d f8 c8 00 00 00 7c af e9 } //3
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*3) >=3
 
}