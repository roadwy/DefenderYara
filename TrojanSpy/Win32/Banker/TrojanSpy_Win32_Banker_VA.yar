
rule TrojanSpy_Win32_Banker_VA{
	meta:
		description = "TrojanSpy:Win32/Banker.VA,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 0a 00 00 "
		
	strings :
		$a_00_0 = {2f 69 6e 66 65 63 74 73 2e 70 68 70 00 } //1
		$a_02_1 = {75 73 65 72 5f 70 72 65 66 28 22 6e 65 74 77 6f 72 6b 2e 70 72 6f 78 79 2e 61 75 74 6f 63 6f 6e 66 69 67 5f 75 72 6c 22 2c 22 68 74 74 70 3a 2f 2f [0-50] 2e 70 61 63 22 29 3b } //1
		$a_02_2 = {51 75 61 6c 69 64 61 64 65 3d [0-10] 50 72 6f 64 75 74 6f [0-10] 50 72 6f 64 75 74 6f 3d [0-10] 6e 6f 6d 65 70 63 3d } //1
		$a_02_3 = {5c 73 74 61 72 74 75 70 5c [0-09] 2e 65 78 65 00 [0-10] 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 4d 65 6e 75 20 49 6e 69 63 69 61 72 5c 50 72 6f 67 72 61 6d 61 73 5c 49 6e 69 63 69 61 6c 69 7a 61 72 5c [0-09] 2e 65 78 65 } //1
		$a_02_4 = {45 6e 61 62 6c 65 48 74 74 70 31 5f 31 00 [0-10] 50 72 6f 78 79 45 6e 61 62 6c 65 00 [0-10] 4d 69 67 72 61 74 65 50 72 6f 78 79 00 } //1
		$a_03_5 = {5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c 50 72 6f 66 69 6c 65 73 5c 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 70 72 65 66 73 2e 6a 73 00 } //1
		$a_03_6 = {2f 31 2e 70 61 63 00 00 [0-09] 41 75 74 6f 43 6f 6e 66 69 67 55 52 4c 00 00 00 } //2
		$a_02_7 = {2e 63 6f 6d 00 00 00 [0-09] 41 75 74 6f 43 6f 6e 66 69 67 55 52 4c 00 00 00 } //1
		$a_02_8 = {75 73 65 72 5f 70 72 65 66 28 22 6e 65 74 77 6f 72 6b 2e 70 72 6f 78 79 2e 61 75 74 6f 63 6f 6e 66 69 67 5f 75 72 6c 22 2c 22 68 74 74 70 3a 2f 2f [0-50] 2e 63 6f 6d 22 29 3b } //1
		$a_01_9 = {61 62 63 2e 70 68 70 00 00 00 00 ff ff ff ff 07 00 00 00 41 42 43 3d 58 52 45 00 ff ff ff ff 04 00 00 00 58 52 45 3d 00 00 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*2+(#a_02_7  & 1)*1+(#a_02_8  & 1)*1+(#a_01_9  & 1)*1) >=4
 
}