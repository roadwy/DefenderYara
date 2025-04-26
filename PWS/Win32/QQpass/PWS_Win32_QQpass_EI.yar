
rule PWS_Win32_QQpass_EI{
	meta:
		description = "PWS:Win32/QQpass.EI,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {25 73 5c 73 79 73 74 65 6d 33 32 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 5c 73 79 73 74 65 6d 33 32 5c 56 33 6c 67 68 74 2e 64 6c 6c 2c 4d 58 48 44 50 55 43 25 63 25 63 64 65 6c } //1 %s\system32\rundll32.exe %s\system32\V3lght.dll,MXHDPUC%c%cdel
		$a_01_1 = {51 75 46 75 3a 25 73 20 20 4e 61 6d 65 3a 25 73 20 20 50 61 73 73 3a 25 73 20 20 4a 69 61 6f 53 65 5f 50 61 73 73 3a 25 73 20 20 43 68 75 61 6e 67 4b 75 5f 50 61 73 73 3a 25 73 } //1 QuFu:%s  Name:%s  Pass:%s  JiaoSe_Pass:%s  ChuangKu_Pass:%s
		$a_01_2 = {6c 6f 67 69 6e 5f 6d 6f 64 65 3d 6c 6f 67 69 6e 26 } //1 login_mode=login&
		$a_01_3 = {4d 58 44 5f 4a 69 61 6f 53 65 } //1 MXD_JiaoSe
		$a_01_4 = {4d 58 44 5f 43 61 6e 67 4b 75 } //1 MXD_CangKu
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
rule PWS_Win32_QQpass_EI_2{
	meta:
		description = "PWS:Win32/QQpass.EI,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 32 2e 6a 70 67 } //1 c:\2.jpg
		$a_01_1 = {6a 7a 79 71 66 68 64 73 6c 69 6e 62 63 } //1 jzyqfhdslinbc
		$a_01_2 = {26 51 51 50 61 73 73 57 6f 72 64 3d 00 3f 51 51 4e 75 6d 62 65 72 3d 00 } //1 儦偑獡坳牯㵤㼀兑畎扭牥=
		$a_01_3 = {31 31 31 30 2f 32 68 67 68 66 2f 6d 61 69 6c 2e 61 73 70 } //1 1110/2hghf/mail.asp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}