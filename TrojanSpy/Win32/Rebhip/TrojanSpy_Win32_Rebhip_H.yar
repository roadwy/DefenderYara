
rule TrojanSpy_Win32_Rebhip_H{
	meta:
		description = "TrojanSpy:Win32/Rebhip.H,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b7 d6 6b fa 47 8b 53 30 8d 54 ba 20 } //1
		$a_01_1 = {0f b7 c6 6b c0 47 8b 53 30 8d 94 82 20 01 00 00 8b 43 30 8d 44 b8 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule TrojanSpy_Win32_Rebhip_H_2{
	meta:
		description = "TrojanSpy:Win32/Rebhip.H,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 50 59 5f 4e 45 54 5f 52 41 54 4d 55 54 45 58 00 } //1
		$a_01_1 = {58 58 2d 2d 58 58 2d 2d 58 58 2e 74 78 74 00 } //1
		$a_01_2 = {6e 6a 6b 76 65 6e 6b 6e 76 6a 65 62 63 64 64 6c 61 6b 6e 76 66 64 76 6a 6b 66 64 73 6b 76 00 } //2
		$a_01_3 = {6e 6a 67 6e 6a 76 65 6a 76 6f 72 65 6e 77 74 72 6e 69 6f 6e 72 69 6f 6e 76 69 72 6f 6e 76 72 6e 76 63 67 31 30 37 00 } //2
		$a_01_4 = {6e 6a 67 6e 6a 76 65 6a 76 6f 72 65 6e 77 74 72 6e 69 6f 6e 72 69 6f 6e 76 69 72 6f 6e 76 72 6e 76 63 67 31 31 37 00 } //2
		$a_01_5 = {23 23 23 23 40 23 23 23 23 20 23 23 23 23 } //1 ####@#### ####
		$a_01_6 = {58 58 2d 58 58 2d 58 58 2d 58 58 } //1 XX-XX-XX-XX
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=2
 
}