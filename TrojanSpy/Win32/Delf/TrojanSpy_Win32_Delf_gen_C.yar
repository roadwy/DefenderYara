
rule TrojanSpy_Win32_Delf_gen_C{
	meta:
		description = "TrojanSpy:Win32/Delf.gen!C,SIGNATURE_TYPE_PEHSTR,41 00 3f 00 0b 00 00 "
		
	strings :
		$a_01_0 = {f7 d9 f7 db 83 d9 00 83 f7 01 89 cd b9 40 00 00 00 57 31 ff 31 f6 d1 e0 d1 d2 d1 d6 d1 d7 39 ef } //50
		$a_01_1 = {40 6e 65 74 74 61 78 69 2e 63 6f 6d } //5 @nettaxi.com
		$a_01_2 = {62 69 6c 6c 67 61 74 65 73 40 6d 6f 63 6f 73 6f 66 74 2e 63 6f 6d } //5 billgates@mocosoft.com
		$a_01_3 = {4d 41 49 4c 20 46 52 4f 4d 3a 20 3c } //1 MAIL FROM: <
		$a_01_4 = {52 43 50 54 20 54 4f 3a 20 3c } //1 RCPT TO: <
		$a_01_5 = {46 72 6f 6d 3a } //1 From:
		$a_01_6 = {53 75 62 6a 65 63 74 3a } //1 Subject:
		$a_01_7 = {57 69 6e 45 78 65 63 } //1 WinExec
		$a_01_8 = {57 53 41 53 74 61 72 74 75 70 } //1 WSAStartup
		$a_01_9 = {67 65 74 68 6f 73 74 62 79 6e 61 6d 65 } //1 gethostbyname
		$a_01_10 = {73 6f 63 6b 65 74 } //1 socket
	condition:
		((#a_01_0  & 1)*50+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=63
 
}