
rule Trojan_Win32_QQpass_CX{
	meta:
		description = "Trojan:Win32/QQpass.CX,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {a3 51 51 4d 67 73 be ee 39 49 7d 0b 72 ca 03 29 01 03 66 b0 41 9a 16 } //1
		$a_01_1 = {31 00 2c 00 20 00 35 00 35 00 2c 00 20 00 31 00 38 00 36 00 31 00 2c 00 20 00 30 00 } //1 1, 55, 1861, 0
		$a_01_2 = {00 65 33 2e 64 6c 6c 00 } //1 攀⸳汤l
		$a_01_3 = {54 58 50 72 6f 78 79 2e 47 65 74 50 72 6f 78 79 44 6c 6c 49 6e 66 6f } //1 TXProxy.GetProxyDllInfo
		$a_01_4 = {68 74 74 70 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 5c } //1 http\shell\open\command\
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 54 45 4e 43 45 4e 54 5c 51 51 32 30 30 39 5c 49 6e 73 74 61 6c 6c } //1 SOFTWARE\TENCENT\QQ2009\Install
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}