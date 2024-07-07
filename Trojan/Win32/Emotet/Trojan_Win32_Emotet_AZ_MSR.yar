
rule Trojan_Win32_Emotet_AZ_MSR{
	meta:
		description = "Trojan:Win32/Emotet.AZ!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {6d 73 70 5f 66 72 65 6e 63 68 2e 64 6c 6c } //1 msp_french.dll
		$a_01_1 = {6d 73 70 5f 64 75 74 63 68 2e 64 6c 6c } //1 msp_dutch.dll
		$a_01_2 = {6d 73 70 5f 69 74 61 6c 69 61 6e 2e 64 6c 6c } //1 msp_italian.dll
		$a_01_3 = {6d 73 70 5f 67 65 72 6d 61 6e 2e 64 6c 6c } //1 msp_german.dll
		$a_01_4 = {6d 73 70 5f 70 6f 72 74 75 67 75 65 73 65 2e 64 6c 6c } //1 msp_portuguese.dll
		$a_01_5 = {6d 73 70 5f 73 70 61 6e 69 73 68 2e 64 6c 6c } //1 msp_spanish.dll
		$a_01_6 = {41 44 5a 58 41 44 44 53 53 51 41 2e 45 58 45 } //1 ADZXADDSSQA.EXE
		$a_01_7 = {59 79 6a 53 4d 49 48 6d 42 62 41 61 70 64 5a 55 57 77 } //1 YyjSMIHmBbAapdZUWw
		$a_01_8 = {61 6c 77 61 79 73 6f 6e 74 6f 70 } //1 alwaysontop
		$a_01_9 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}