
rule PWS_Win32_QQpass_DU{
	meta:
		description = "PWS:Win32/QQpass.DU,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 61 6b 65 57 73 32 68 65 6c 70 44 4c 4c } //1 FakeWs2helpDLL
		$a_01_1 = {47 45 54 20 2f 70 6f 73 74 64 61 74 61 2e 61 73 70 20 48 54 54 50 2f 31 2e 31 } //1 GET /postdata.asp HTTP/1.1
		$a_01_2 = {26 51 51 4e 75 6d 62 65 72 3d 25 73 26 51 51 50 61 73 73 57 6f 72 64 3d 25 73 } //1 &QQNumber=%s&QQPassWord=%s
		$a_01_3 = {41 75 74 6f 4c 6f 67 69 6e 2e 64 62 } //1 AutoLogin.db
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule PWS_Win32_QQpass_DU_2{
	meta:
		description = "PWS:Win32/QQpass.DU,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 81 3e 4d 5a 0f 85 16 01 00 00 8b 56 3c 03 d6 89 54 24 10 81 3a 50 45 00 00 0f 85 01 01 00 00 } //1
		$a_01_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 51 51 2e 65 78 65 20 2f 74 } //1 taskkill /f /im QQ.exe /t
		$a_01_2 = {45 53 45 54 20 4e 4f 44 33 32 20 41 6e 74 69 76 69 72 75 73 } //1 ESET NOD32 Antivirus
		$a_01_3 = {53 69 7a 65 6f 66 52 65 73 6f 75 72 63 65 } //1 SizeofResource
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}