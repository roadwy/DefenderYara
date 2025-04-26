
rule PWS_Win32_QQpass_CJL{
	meta:
		description = "PWS:Win32/QQpass.CJL,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_00_0 = {85 c0 7e 1a 8a 93 b8 60 40 00 30 16 46 43 81 e3 07 00 00 80 79 05 4b 83 cb f8 43 48 75 e6 5f 5e 5b c3 } //20
		$a_00_1 = {8b d8 eb 01 4b 85 db 7e 15 80 7c 1e ff 5c 74 0e 80 7c 1e ff 3a 74 07 80 7c 1e ff 2f 75 e6 57 8b c6 } //10
		$a_00_2 = {6a 00 6a 06 6a 02 6a 00 6a 00 68 00 00 00 c0 8b 45 fc 50 e8 22 f8 ff ff 8b d8 83 fb ff 74 58 57 a1 50 76 40 00 50 e8 c7 f8 ff ff } //10
		$a_01_3 = {00 4d 73 67 48 6f 6f 6b } //1 䴀杳潈歯
		$a_00_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
	condition:
		((#a_00_0  & 1)*20+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=22
 
}