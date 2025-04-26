
rule Trojan_Win32_Emotet_AU{
	meta:
		description = "Trojan:Win32/Emotet.AU,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 16 8d 49 08 33 55 08 8d 76 04 0f b6 c2 47 66 89 41 f8 8b c2 c1 e8 08 0f b6 c0 66 89 41 fa c1 ea 10 0f b6 c2 66 89 41 fc c1 ea 08 0f b6 c2 66 89 41 fe 3b fb 72 c9 } //2
		$a_03_1 = {8b 16 8d 49 04 [0-06] 8d 76 04 88 51 fc 8b c2 c1 e8 08 47 c1 ea 10 88 41 fd 88 51 fe c1 ea 08 88 51 ff 3b fb 72 } //2
		$a_01_2 = {66 83 38 5c 74 0b 83 c0 02 66 83 38 00 75 f1 eb 06 33 c9 66 89 48 02 6a 00 } //1
		$a_03_3 = {83 c4 04 33 c9 39 4d 14 8b f0 0f 45 ce 6a 00 68 00 c3 4c 84 6a 00 6a 00 6a 00 [0-03] 51 57 ff 15 ?? ?? ?? ?? 56 6a 00 8b f8 ff 15 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=6
 
}
rule Trojan_Win32_Emotet_AU_2{
	meta:
		description = "Trojan:Win32/Emotet.AU,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0a 00 00 "
		
	strings :
		$a_03_0 = {8d 45 a8 50 6a 00 6a 00 ff 75 08 6a 00 6a 00 6a 00 6a 00 56 ff 15 ?? ?? ?? ?? 85 c0 74 36 8b 45 0c 85 c0 74 13 f3 0f 6f 45 f0 f3 0f 7f 00 b8 01 00 00 00 } //1
		$a_03_1 = {ff 75 f0 ff 15 ?? ?? ?? ?? ff 75 f4 ff 15 ?? ?? ?? ?? b8 01 00 00 00 5e 8b e5 5d } //1
		$a_03_2 = {74 05 e8 72 dd ff ff 6a 00 ff 15 ?? ?? ?? ?? 8b e5 5d } //1
		$a_03_3 = {68 04 01 00 00 68 ?? ?? ?? ?? 6a 00 ff 15 } //1
		$a_01_4 = {74 1d 8d a4 24 00 00 00 00 80 f9 2c 74 11 66 0f be c9 40 66 89 0e 83 c6 02 8a 08 84 c9 75 ea e9 } //1
		$a_01_5 = {c7 85 7c fa ff ff 6b 27 76 ce c7 85 80 fa ff ff db a1 63 b9 c7 85 84 fa ff ff 7a 02 e2 97 } //1
		$a_01_6 = {c7 45 84 2e b2 c9 70 c7 45 88 42 45 ff e3 } //1
		$a_01_7 = {c7 85 e0 f9 ff ff e5 c3 13 37 c7 85 e4 f9 ff ff c2 8e fd 06 c7 85 e8 f9 ff ff 6d 26 8e 9c } //1
		$a_01_8 = {74 58 49 48 5c 68 07 45 88 be ff 26 9b } //1
		$a_01_9 = {c7 45 f8 e6 61 c7 b9 c7 45 fc b1 7a c0 70 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=5
 
}