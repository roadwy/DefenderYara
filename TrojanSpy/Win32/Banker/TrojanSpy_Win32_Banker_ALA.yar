
rule TrojanSpy_Win32_Banker_ALA{
	meta:
		description = "TrojanSpy:Win32/Banker.ALA,SIGNATURE_TYPE_PEHSTR_EXT,07 00 05 00 0a 00 00 "
		
	strings :
		$a_03_0 = {66 83 eb 03 66 ff 45 f6 66 83 fb 01 77 b1 8d 45 e4 50 0f b7 d3 b9 03 00 00 00 8b 45 fc ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b f8 66 2b 7d f8 0f b7 45 f6 66 03 45 fa 66 2b f8 8d 45 e0 8b d7 } //3
		$a_03_1 = {74 00 70 00 70 00 2e 00 64 00 61 00 74 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 73 00 63 00 62 00 } //1
		$a_03_2 = {2e 00 2f 00 69 00 6e 00 66 00 65 00 2f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 6d 00 73 00 6e 00 } //1
		$a_03_3 = {2e 00 2f 00 69 00 6e 00 66 00 6f 00 2f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 55 00 53 00 52 00 } //1
		$a_03_4 = {3f 00 74 00 69 00 70 00 6f 00 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 00 6e 00 6f 00 6d 00 65 00 3d 00 } //1
		$a_03_5 = {53 00 45 00 4d 00 41 00 2e 00 53 00 43 00 42 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 53 00 45 00 4d 00 41 00 32 00 2e 00 53 00 43 00 42 00 } //1
		$a_03_6 = {33 d2 b8 1c 00 00 00 e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8d 4d ?? 33 d2 b8 26 00 00 00 e8 } //1
		$a_03_7 = {74 00 70 00 70 00 2e 00 64 00 61 00 74 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 74 00 78 00 74 00 } //1
		$a_03_8 = {2e 00 2f 00 69 00 6e 00 66 00 65 00 2f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 3f 00 74 00 69 00 70 00 6f 00 3d 00 } //1
		$a_03_9 = {26 00 6e 00 6f 00 6d 00 65 00 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 00 64 00 61 00 64 00 6f 00 73 00 3d 00 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*1+(#a_03_7  & 1)*1+(#a_03_8  & 1)*1+(#a_03_9  & 1)*1) >=5
 
}