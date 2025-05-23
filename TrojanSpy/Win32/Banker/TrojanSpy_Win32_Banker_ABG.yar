
rule TrojanSpy_Win32_Banker_ABG{
	meta:
		description = "TrojanSpy:Win32/Banker.ABG,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {ba 03 00 00 00 e8 ?? ?? ?? ?? 8b 85 ?? ff ff ff e8 ?? ?? ?? ?? 50 6a 00 e8 ?? ?? ?? ?? 8b ?? 6a 01 } //1
		$a_03_1 = {eb 07 b2 02 e8 ?? ?? ff ff 8b 45 fc 80 78 5b 00 74 ?? 8b 45 fc 8b 40 44 80 b8 ?? ?? 00 00 01 ?? ?? 8b ?? fc } //1
		$a_00_2 = {0e 54 4b 65 79 50 72 65 73 73 45 76 65 6e 74 } //1
		$a_00_3 = {53 69 6c 65 6e 74 } //1 Silent
		$a_00_4 = {70 61 73 73 77 6f 72 64 } //1 password
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule TrojanSpy_Win32_Banker_ABG_2{
	meta:
		description = "TrojanSpy:Win32/Banker.ABG,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0d 00 07 00 00 "
		
	strings :
		$a_01_0 = {eb 05 be 01 00 00 00 8b 45 0c 0f b6 44 30 ff 33 c3 89 45 e8 3b 7d e8 7c 0f 8b 45 e8 05 ff 00 00 00 2b c7 89 45 e8 eb 03 29 7d e8 8d 45 bc 8b 55 e8 e8 } //10
		$a_01_1 = {21 73 72 63 3d 22 68 74 74 70 73 3a 2f 2f 62 72 61 64 65 73 63 6f 6e 65 74 65 6d 70 72 65 73 61 2e 63 06 21 6f 6d 2e 62 72 2f } //1 猡捲∽瑨灴㩳⼯牢摡獥潣敮整灭敲慳挮℆浯戮⽲
		$a_01_2 = {6f 72 6b 75 74 2e 63 6f 6d 2f 69 6d 67 2f 67 77 74 2f 69 6e 70 75 74 2d 62 74 6e 2d 68 74 6d 6c 2e 70 6e 67 00 } //1
		$a_01_3 = {69 6e 73 65 72 74 73 71 6c 2e 70 68 70 3f 00 } //1
		$a_01_4 = {75 70 64 61 74 65 73 71 6c 2e 70 68 70 3f 00 } //1
		$a_01_5 = {2f 00 70 00 70 00 73 00 65 00 63 00 75 00 72 00 65 00 2f 00 73 00 68 00 61 00 31 00 61 00 75 00 74 00 68 00 2e 00 73 00 72 00 66 00 } //1 /ppsecure/sha1auth.srf
		$a_01_6 = {5f 53 43 52 49 50 54 5f 50 41 53 54 45 5f 55 52 4c 41 43 54 49 4f 4e 5f 49 46 5f 50 52 4f 4d 50 54 00 } //1 卟剃偉彔䅐呓彅剕䅌呃佉彎䙉偟佒偍T
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=13
 
}