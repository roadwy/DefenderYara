
rule Trojan_Win32_Bingoml_MA_MTB{
	meta:
		description = "Trojan:Win32/Bingoml.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 07 00 00 "
		
	strings :
		$a_01_0 = {ce b9 27 40 64 91 83 ae cb 0f 73 c2 0e ce 21 a3 42 c3 03 a3 a7 8f 50 62 9d 73 f8 07 ff 05 d4 be 0c e4 dd f7 99 a6 6e 11 01 d0 d2 fa 0e af 23 9a } //10
		$a_01_1 = {30 95 77 b1 d4 3a 6b 88 d1 55 b0 45 49 85 6b a9 3f 6e 98 a0 06 9e 0c 44 f8 0d 6b df b4 6f 95 9d e7 e8 04 27 96 a6 5f 18 55 27 ac 8d 07 e8 d2 5a } //10
		$a_01_2 = {66 72 6d 46 6f 72 67 6f 74 50 61 73 73 77 6f 72 64 } //2 frmForgotPassword
		$a_01_3 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 69 00 6d 00 20 00 } //2 taskkill /im 
		$a_01_4 = {5b 00 20 00 41 00 4c 00 54 00 44 00 4f 00 57 00 4e 00 20 00 5d 00 } //2 [ ALTDOWN ]
		$a_01_5 = {20 00 5b 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 73 00 5d 00 } //2  [Passwords]
		$a_01_6 = {53 00 20 00 20 00 75 00 20 00 20 00 72 00 20 00 20 00 65 00 } //2 S  u  r  e
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=30
 
}