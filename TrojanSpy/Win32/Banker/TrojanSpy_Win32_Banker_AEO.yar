
rule TrojanSpy_Win32_Banker_AEO{
	meta:
		description = "TrojanSpy:Win32/Banker.AEO,SIGNATURE_TYPE_PEHSTR_EXT,09 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {7e 2b be 01 00 00 00 8d 45 f0 8b d7 52 8b 55 fc 8a 54 32 ff 59 2a d1 f6 d2 e8 } //4
		$a_01_1 = {a4 87 7a 8b 9d 80 be } //2
		$a_01_2 = {a5 a1 a5 ae a0 b8 bd ab a6 b0 a5 9d a1 b8 cb d1 a5 a7 a4 a8 af a7 af a6 a0 a5 } //2
		$a_01_3 = {80 7b 76 75 88 7d 88 85 7a } //2
		$a_01_4 = {94 9d 81 8a 7c 79 8f 7e 8b 94 a3 87 8d 7e 81 7d 81 8a 7c 94 99 87 82 } //1
		$a_01_5 = {8c 81 79 7d 94 ad 7b 7e 7e 8b 82 7c 9a 8b 7e 7d 87 81 82 94 9e 7b 82 } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}