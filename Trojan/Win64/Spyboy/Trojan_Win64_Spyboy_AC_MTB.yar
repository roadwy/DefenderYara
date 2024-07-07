
rule Trojan_Win64_Spyboy_AC_MTB{
	meta:
		description = "Trojan:Win64/Spyboy.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {5c 00 5c 00 2e 00 5c 00 5a 00 65 00 6d 00 61 00 6e 00 61 00 41 00 6e 00 74 00 69 00 4d 00 61 00 6c 00 77 00 61 00 72 00 65 00 } //1 \\.\ZemanaAntiMalware
		$a_01_1 = {54 65 72 6d 69 6e 61 74 69 6e 67 20 41 4c 4c 20 45 44 52 2f 58 44 52 2f 41 56 73 } //1 Terminating ALL EDR/XDR/AVs
		$a_01_2 = {61 76 61 73 74 } //1 avast
		$a_01_3 = {63 61 72 62 6f 6e 62 6c 61 63 6b } //1 carbonblack
		$a_01_4 = {63 72 6f 77 64 73 74 72 69 6b 65 } //1 crowdstrike
		$a_01_5 = {63 79 6c 61 6e 63 65 } //1 cylance
		$a_01_6 = {64 65 66 65 6e 64 65 72 } //1 defender
		$a_01_7 = {6b 61 73 70 65 72 73 6b 79 } //1 kaspersky
		$a_01_8 = {6d 61 6e 64 69 61 6e 74 } //1 mandiant
		$a_01_9 = {6d 63 61 66 65 65 } //1 mcafee
		$a_01_10 = {70 61 6c 6f 20 61 6c 74 6f 20 6e 65 74 77 6f 72 6b 73 } //1 palo alto networks
		$a_01_11 = {73 6f 70 68 6f 73 } //1 sophos
		$a_01_12 = {73 79 6d 61 6e 74 65 63 } //1 symantec
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}