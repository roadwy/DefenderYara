
rule Trojan_Win32_Febipos_gen_A{
	meta:
		description = "Trojan:Win32/Febipos.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 0b 00 00 "
		
	strings :
		$a_01_0 = {25 73 5c 31 2e 63 72 78 00 } //1
		$a_01_1 = {25 73 5c 74 65 6d 70 2e 63 72 78 00 } //1
		$a_01_2 = {6b 65 79 22 3a 20 22 4d 49 47 66 4d 41 30 47 43 53 71 47 53 49 62 33 44 51 45 42 41 } //1 key": "MIGfMA0GCSqGSIb3DQEBA
		$a_01_3 = {66 69 72 65 66 6f 78 2e 65 78 65 00 46 61 63 65 62 6f 6f 6b 20 55 70 64 61 74 65 } //1
		$a_01_4 = {40 66 61 63 65 62 6f 6f 6b 2e 63 6f 6d 2e 78 70 69 } //1 @facebook.com.xpi
		$a_01_5 = {53 74 61 72 74 3d 61 75 74 6f 0a 00 53 74 61 72 74 4e 6f 77 3d 74 72 75 65 0a 00 } //1
		$a_01_6 = {74 04 c6 45 e2 01 8b 45 e8 8d 14 85 00 00 00 00 8b 45 d4 01 d0 c7 } //2
		$a_03_7 = {74 04 c6 45 e2 01 8a 45 e2 83 f0 01 84 c0 74 7e 8b 85 ?? ?? ff ff 89 04 24 e8 ?? ?? ?? ?? 89 45 e4 eb 01 90 90 8b 85 ?? ?? ff ff 89 04 24 e8 } //2
		$a_03_8 = {3b 45 e4 7c cf eb 08 83 7d ?? 65 75 a6 eb 02 eb a2 8b 45 f4 40 89 45 } //2
		$a_01_9 = {89 45 d8 eb 58 8a 45 f3 83 f0 01 84 c0 74 15 8b 45 dc 89 44 24 04 8d 85 d8 f5 ff ff 89 04 24 e8 } //2
		$a_03_10 = {7c c2 eb 08 83 7d ?? 65 75 99 eb 02 eb 95 8a 45 e3 83 f0 01 84 c0 0f 84 7e 02 00 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*2+(#a_03_7  & 1)*2+(#a_03_8  & 1)*2+(#a_01_9  & 1)*2+(#a_03_10  & 1)*2) >=7
 
}