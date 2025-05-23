
rule Trojan_Win32_Trickbot_AAA{
	meta:
		description = "Trojan:Win32/Trickbot.AAA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 09 00 00 "
		
	strings :
		$a_03_0 = {80 0a a0 c9 48 83 c3 20 80 0a a0 cd 48 3b de 80 0a a0 d0 75 ?? 80 0a a0 d2 48 8b 97 b0 01 00 00 80 0a a0 d9 4c 8b 87 c0 01 00 00 80 0a a0 e0 4c 2b c2 80 0a a0 e3 49 c1 f8 05 80 0a a0 e7 e8 ?? ?? ?? ?? 80 0a a0 ec 90 90 80 0a a0 ed 33 c0 80 0a a0 ef 48 89 87 b0 01 00 00 80 0a a0 f6 48 89 87 b8 01 00 00 80 0a a0 fd 48 89 87 c0 01 00 00 80 0a a1 04 48 8b cf } //1
		$a_03_1 = {8b 8f dc 01 00 00 85 c9 74 5b ff 75 f0 8b 97 e0 01 00 00 51 e8 ?? ?? ?? ?? 8b 8f e4 01 00 00 b8 93 24 49 92 2b 8f dc 01 00 00 83 c4 08 f7 e9 03 d1 c1 fa 06 8b c2 c1 e8 1f 03 c2 } //1
		$a_03_2 = {64 6c 6c 00 43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72 00 52 65 6c 65 61 ?? 65 00 53 74 61 72 74 00 00 00 00 } //1
		$a_03_3 = {70 50 61 72 65 6e 74 44 61 74 ?? 20 69 73 20 6e 75 6c 6c 00 00 00 00 00 } //1
		$a_03_4 = {53 74 61 72 74 28 29 20 63 61 6c 6c ?? 64 2c 20 6d 6f 64 75 6c 65 20 68 61 6e 64 6c 65 20 00 00 00 00 00 } //1
		$a_03_5 = {52 65 6c 65 61 73 65 28 29 20 63 61 6c 6c 65 ?? 2c 20 6d 6f 64 75 6c 65 20 68 61 6e 64 6c 65 20 00 00 00 00 00 00 00 } //1
		$a_03_6 = {43 6f 6e 74 72 6f 6c 28 29 20 2d 3e 20 64 70 6f 73 74 20 63 61 6c ?? 65 64 2c 20 6d 6f 64 75 6c 65 20 68 61 6e 64 6c 65 20 00 00 00 00 00 00 } //1
		$a_03_7 = {63 3a 5c 74 65 6d 70 5c 63 6f ?? 6b 69 65 73 2e 6c 6f 67 00 00 00 00 } //1
		$a_03_8 = {57 61 6e 74 52 65 6c 65 ?? 73 65 00 00 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*1+(#a_03_7  & 1)*1+(#a_03_8  & 1)*1) >=2
 
}