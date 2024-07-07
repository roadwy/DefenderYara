
rule Trojan_Win32_Hideproc_H{
	meta:
		description = "Trojan:Win32/Hideproc.H,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {61 00 62 00 63 00 63 00 62 00 61 00 25 00 64 00 64 00 61 00 64 00 } //1 abccba%ddad
		$a_01_1 = {00 00 6e 00 74 00 64 00 6c 00 6c 00 2e 00 64 00 6c 00 6c 00 00 00 } //1
		$a_01_2 = {68 69 64 65 70 72 6f 63 65 73 73 } //1 hideprocess
		$a_03_3 = {68 6f 6f 6b 5f 70 72 6f 63 65 73 73 90 02 10 73 73 6c 90 00 } //1
		$a_01_4 = {73 73 6c 00 3f 75 6e 68 6f 6f 6b 5f 70 72 6f 63 65 73 73 } //1
		$a_01_5 = {67 5f 66 75 6e 5f 5a 77 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 g_fun_ZwQuerySystemInformation
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}