
rule TrojanSpy_Win32_Bhoban_B{
	meta:
		description = "TrojanSpy:Win32/Bhoban.B,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1e 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 0a ff 45 e8 ff 4d fc 74 21 eb e2 8b 45 e8 d1 e0 03 45 ec 03 45 08 0f b7 00 c1 e0 02 03 45 f0 03 45 08 } //10
		$a_01_1 = {00 10 85 c0 74 11 8b 55 08 c6 02 e9 8b 45 0c 2b c2 83 e8 05 89 42 01 c9 c2 08 00 } //10
		$a_01_2 = {8a 11 80 ca 20 03 c2 90 8d 49 02 66 39 19 75 f0 3d e0 1e 00 00 75 5e c7 44 3c 1c 01 00 00 80 } //10
		$a_01_3 = {43 6c 6f 73 65 47 75 61 72 64 } //1 CloseGuard
		$a_01_4 = {00 61 64 6c 6c 2e 64 6c 6c 00 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=30
 
}