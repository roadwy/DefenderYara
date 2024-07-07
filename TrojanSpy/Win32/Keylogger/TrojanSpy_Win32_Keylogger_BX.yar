
rule TrojanSpy_Win32_Keylogger_BX{
	meta:
		description = "TrojanSpy:Win32/Keylogger.BX,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 63 6d 64 2e 68 74 6d 6c } //1 \cmd.html
		$a_01_1 = {73 00 76 00 76 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //1 svvhost.exe
		$a_01_2 = {4c 00 6f 00 67 00 20 00 4f 00 66 00 20 00 4b 00 65 00 79 00 4c 00 6f 00 67 00 67 00 65 00 72 00 } //1 Log Of KeyLogger
		$a_01_3 = {5b 00 20 00 41 00 6e 00 74 00 69 00 20 00 56 00 69 00 72 00 75 00 73 00 20 00 54 00 61 00 72 00 67 00 65 00 74 00 20 00 53 00 68 00 6f 00 6d 00 61 00 } //1 [ Anti Virus Target Shoma
		$a_01_4 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 66 00 72 00 6f 00 6d 00 20 00 46 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 } //1 Select * from FirewallProduct
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}