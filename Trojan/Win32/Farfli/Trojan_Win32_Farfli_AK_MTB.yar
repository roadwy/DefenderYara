
rule Trojan_Win32_Farfli_AK_MTB{
	meta:
		description = "Trojan:Win32/Farfli.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {31 ab 3b 5e ad 43 8e 19 89 e8 1b be 88 12 80 e7 12 e3 ee 7b eb } //1
		$a_01_1 = {25 73 2e 65 78 65 } //1 %s.exe
		$a_01_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}