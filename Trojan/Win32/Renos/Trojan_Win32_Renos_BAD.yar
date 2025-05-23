
rule Trojan_Win32_Renos_BAD{
	meta:
		description = "Trojan:Win32/Renos.BAD,SIGNATURE_TYPE_PEHSTR,08 00 08 00 07 00 00 "
		
	strings :
		$a_01_0 = {44 72 69 76 65 72 20 64 69 73 6b 2e 73 79 73 20 69 73 20 6f 75 74 20 6f 66 20 6d 65 6d 6f 72 79 00 } //2
		$a_01_1 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 69 73 20 69 6e 66 65 63 74 65 64 21 20 49 74 20 69 73 20 72 65 63 6f 6d 6d 65 6e 64 65 64 20 74 6f 20 73 74 61 72 74 20 73 70 79 77 61 72 65 20 63 6c 65 61 6e 65 72 20 74 6f 6f 6c 2e 00 } //2
		$a_01_2 = {57 61 72 6e 69 6e 67 21 20 53 65 63 75 72 69 74 79 20 72 65 70 6f 72 74 } //2 Warning! Security report
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 } //2 Software\Microsoft\Security Center
		$a_01_4 = {41 63 63 65 73 73 20 76 69 6f 6c 61 74 69 6f 6e 20 61 74 20 61 64 64 72 65 73 73 } //1 Access violation at address
		$a_01_5 = {4e 6f 43 68 61 6e 67 69 6e 67 57 61 6c 6c 70 61 70 65 72 00 } //1 潎桃湡楧杮慗汬慰数r
		$a_01_6 = {44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=8
 
}