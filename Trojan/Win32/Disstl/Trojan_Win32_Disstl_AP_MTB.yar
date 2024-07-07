
rule Trojan_Win32_Disstl_AP_MTB{
	meta:
		description = "Trojan:Win32/Disstl.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {73 65 6e 64 68 6f 6f 6b 66 69 6c 65 2e 65 78 65 } //1 sendhookfile.exe
		$a_81_1 = {43 3a 2f 74 65 6d 70 2f 57 65 62 42 72 6f 77 73 65 72 50 61 73 73 56 69 65 77 2e 65 78 65 } //1 C:/temp/WebBrowserPassView.exe
		$a_81_2 = {43 3a 2f 74 65 6d 70 2f 50 61 73 73 77 6f 72 64 73 2e 74 78 74 } //1 C:/temp/Passwords.txt
		$a_81_3 = {42 72 6f 77 73 65 72 20 50 61 73 73 77 6f 72 64 21 } //1 Browser Password!
		$a_81_4 = {50 61 73 73 77 6f 72 64 73 2e 74 78 74 20 6e 6f 74 20 66 6f 75 6e 64 } //1 Passwords.txt not found
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}