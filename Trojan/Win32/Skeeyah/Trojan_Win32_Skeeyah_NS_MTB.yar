
rule Trojan_Win32_Skeeyah_NS_MTB{
	meta:
		description = "Trojan:Win32/Skeeyah.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {5f 63 72 74 5f 64 65 62 75 67 67 65 72 5f 68 6f 6f 6b } //1 _crt_debugger_hook
		$a_01_1 = {5f 69 6e 76 6f 6b 65 5f 77 61 74 73 6f 6e } //1 _invoke_watson
		$a_01_2 = {6f 62 6a 65 63 74 5f 68 6f 6f 6b } //1 object_hook
		$a_01_3 = {75 74 66 5f 33 32 5f 64 65 63 6f 64 65 } //1 utf_32_decode
		$a_01_4 = {74 6f 6b 65 6e 69 7a 65 2e 70 79 63 50 4b } //1 tokenize.pycPK
		$a_01_5 = {63 6d 64 2e 70 79 63 50 4b } //1 cmd.pycPK
		$a_01_6 = {48 56 4a 55 } //1 HVJU
		$a_01_7 = {70 79 32 65 78 65 } //1 py2exe
		$a_01_8 = {75 79 2a 3a 4d } //1 uy*:M
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}