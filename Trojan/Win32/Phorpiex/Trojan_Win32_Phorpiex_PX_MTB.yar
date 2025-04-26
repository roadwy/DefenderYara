
rule Trojan_Win32_Phorpiex_PX_MTB{
	meta:
		description = "Trojan:Win32/Phorpiex.PX!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 41 } //1 GetStartupInfoA
		$a_01_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 57 } //1 ShellExecuteW
		$a_01_2 = {77 00 74 00 34 00 77 00 74 00 77 00 34 00 74 00 77 00 34 00 74 00 77 00 34 00 74 00 77 00 34 00 74 00 } //1 wt4wtw4tw4tw4tw4t
		$a_01_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 74 00 72 00 69 00 6b 00 2e 00 77 00 73 00 2f 00 70 00 2e 00 6a 00 70 00 67 00 } //1 http://trik.ws/p.jpg
		$a_01_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 74 00 72 00 69 00 6b 00 2e 00 77 00 73 00 2f 00 70 00 63 00 2e 00 65 00 78 00 65 00 } //1 http://trik.ws/pc.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}