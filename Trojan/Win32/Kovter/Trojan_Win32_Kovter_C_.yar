
rule Trojan_Win32_Kovter_C_{
	meta:
		description = "Trojan:Win32/Kovter.C!!Kovter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,0e 00 0e 00 0f 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 8a 44 18 ff 24 0f 8b 55 f8 8a 54 32 ff 80 e2 0f 32 c2 88 45 f3 8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc 8a 54 1a ff 80 e2 f0 } //10
		$a_01_1 = {3e 00 3e 00 75 00 70 00 64 00 69 00 64 00 00 00 } //1
		$a_01_2 = {6d 00 6f 00 64 00 65 00 3d 00 32 00 26 00 64 00 6f 00 6e 00 65 00 3d 00 31 00 26 00 63 00 6d 00 64 00 69 00 64 00 3d 00 00 00 } //1
		$a_01_3 = {61 00 64 00 64 00 68 00 65 00 61 00 64 00 65 00 72 00 73 00 3d 00 31 00 26 00 55 00 49 00 44 00 3d 00 00 00 } //1
		$a_01_4 = {6d 00 6f 00 64 00 65 00 3d 00 34 00 26 00 55 00 49 00 44 00 3d 00 00 00 } //1
		$a_01_5 = {26 00 4f 00 53 00 62 00 69 00 74 00 3d 00 00 00 } //1
		$a_01_6 = {6c 00 69 00 6d 00 69 00 74 00 62 00 6c 00 61 00 6e 00 6b 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 75 00 73 00 65 00 00 00 } //1
		$a_01_7 = {74 72 79 20 7b 6a 77 70 6c 61 79 65 72 28 29 2e 70 6c 61 79 28 29 7d } //1 try {jwplayer().play()}
		$a_03_8 = {3c 61 20 68 72 65 66 3d 27 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 27 3e 63 6c 69 63 6b 3c 2f 61 3e } //1
		$a_03_9 = {2e 52 75 6e 28 22 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 69 65 78 20 24 65 6e 76 3a } //1
		$a_03_10 = {6d 73 68 74 61 20 22 6a 61 76 61 73 63 72 69 70 74 3a [0-10] 3d 6e 65 77 20 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 3b } //1
		$a_01_11 = {3d 6e 65 77 25 32 30 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 3b 00 } //1
		$a_01_12 = {3e 00 3e 00 70 00 61 00 74 00 68 00 00 00 } //1
		$a_01_13 = {8a 54 32 ff 80 e2 0f 32 c2 88 45 f3 } //1
		$a_03_14 = {33 c0 8a 03 ba 02 00 00 00 e8 ?? ?? ?? ?? 8b 55 ?? 8b c7 e8 ?? ?? ?? ?? 43 4e 75 e1 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_03_8  & 1)*1+(#a_03_9  & 1)*1+(#a_03_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_03_14  & 1)*1) >=14
 
}