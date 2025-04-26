
rule Trojan_Win32_Vundo_gen_CD{
	meta:
		description = "Trojan:Win32/Vundo.gen!CD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_03_0 = {ff d7 46 eb cd c7 45 ?? ff ff ff ff be 01 00 00 00 89 75 fc f6 40 17 20 8b 40 28 74 ?? 03 c3 89 45 ?? 8b 55 08 52 56 53 ff d0 } //2
		$a_01_1 = {8d 8c 08 90 90 90 90 89 4b 0c 31 0b 8b 4b 0c 31 4b 04 8b 53 0c 31 53 08 eb 09 } //1
		$a_01_2 = {83 fa 3c 72 38 81 fa 00 00 20 00 77 30 8d 41 1c 89 45 e4 39 10 75 26 } //1
		$a_03_3 = {7d 2d 8b bd ?? ?? ff ff 81 c7 ?? ?? ?? ?? 89 bd ?? ?? ff ff 0f be f0 33 d2 8a 96 ?? ?? ?? ?? 03 d7 88 54 35 ?? fe c0 88 85 ?? ?? ff ff eb cb } //1
		$a_03_4 = {73 30 0f b7 c9 8b f1 c1 ee 0e c1 e1 02 33 ce 89 8d ?? ?? ff ff 0f b6 f0 33 db 8a 9e ?? ?? ?? ?? 2b d9 88 5c 35 ?? fe c0 88 85 ?? ?? ff ff 33 db eb cc } //1
		$a_03_5 = {73 2e 8b f0 c1 e6 17 c1 e8 09 0b c6 89 85 ?? ?? ff ff 0f b6 f1 33 db 8a 1c b5 ?? ?? ?? ?? 2b d8 88 5c 35 ?? fe c1 88 8d ?? ?? ff ff 33 db eb ce } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=3
 
}