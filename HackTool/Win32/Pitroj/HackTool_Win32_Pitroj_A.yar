
rule HackTool_Win32_Pitroj_A{
	meta:
		description = "HackTool:Win32/Pitroj.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 61 63 6b 53 70 79 20 54 72 6f 6a 61 6e 20 45 78 70 6c 6f 69 74 2e 70 79 74 } //1 HackSpy Trojan Exploit.pyt
		$a_01_1 = {73 74 65 70 20 31 2d 3e 63 6c 69 63 6b 20 6f 6e 20 62 75 69 6c 64 20 74 72 6f 6a 61 6e 20 62 75 74 74 6f 6e } //1 step 1->click on build trojan button
		$a_01_2 = {54 68 69 73 20 74 6f 6f 6c 20 77 61 73 20 62 75 69 6c 64 20 62 79 20 50 72 61 62 68 61 74 20 41 77 61 73 74 68 69 } //1 This tool was build by Prabhat Awasthi
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}