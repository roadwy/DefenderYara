
rule Trojan_Win32_Bingoml_R_MTB{
	meta:
		description = "Trojan:Win32/Bingoml.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {73 76 6d 74 6f 6f 6c 73 64 2e 65 78 65 } //1 svmtoolsd.exe
		$a_81_1 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 57 69 6e 4b 73 } //1 C:\ProgramData\WinKs
		$a_81_2 = {77 69 6e 64 6f 77 73 63 65 72 2e 73 68 6f 70 2f 61 64 6d 69 6e 2f 6c 6f 67 69 6e 2e 70 68 70 } //1 windowscer.shop/admin/login.php
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}