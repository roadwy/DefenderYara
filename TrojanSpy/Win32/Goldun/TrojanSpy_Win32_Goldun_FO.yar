
rule TrojanSpy_Win32_Goldun_FO{
	meta:
		description = "TrojanSpy:Win32/Goldun.FO,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {2a 62 61 72 63 6c 61 79 73 2e 63 6f 2e 75 6b 2a } //1 *barclays.co.uk*
		$a_01_1 = {2a 33 36 35 6f 6e 6c 69 6e 65 2e 63 6f 6d 2a } //1 *365online.com*
		$a_01_2 = {2a 49 42 4c 6f 67 6f 6e 2e 6a 73 70 2a } //1 *IBLogon.jsp*
		$a_01_3 = {2a 2f 4c 6f 67 6f 6e 2d 50 69 6e 50 61 73 73 2e 61 73 70 2a } //1 */Logon-PinPass.asp*
		$a_01_4 = {50 4f 50 33 3a 25 73 } //1 POP3:%s
		$a_01_5 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 76 68 6f 73 74 2e 65 78 65 } //1 C:\WINDOWS\svhost.exe
		$a_01_6 = {5f 00 70 00 61 00 73 00 73 00 2e 00 74 00 78 00 74 00 } //2 _pass.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*2) >=7
 
}