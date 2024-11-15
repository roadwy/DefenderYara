
rule _PseudoThreat_c0000cb6{
	meta:
		description = "!PseudoThreat_c0000cb6,SIGNATURE_TYPE_PEHSTR,22 00 21 00 07 00 00 "
		
	strings :
		$a_01_0 = {73 00 68 00 65 00 72 00 69 00 66 00 66 00 2e 00 65 00 78 00 65 00 00 00 77 } //10
		$a_01_1 = {49 6e 74 65 72 6e 65 74 47 65 74 43 6f 6e 6e 65 63 74 65 64 53 74 61 74 65 } //10 InternetGetConnectedState
		$a_01_2 = {67 65 74 68 6f 73 74 62 79 6e 61 6d 65 } //10 gethostbyname
		$a_01_3 = {53 79 73 74 65 6d 20 65 72 72 6f 72 3a 20 73 70 79 77 61 72 65 20 69 6e 74 72 75 73 69 6f 6e 20 64 65 74 65 63 74 65 64 21 } //1 System error: spyware intrusion detected!
		$a_01_4 = {43 72 69 74 69 63 61 6c 20 65 72 72 6f 72 3a 20 73 79 73 74 65 6d 20 69 6e 20 64 61 6e 67 65 72 21 } //1 Critical error: system in danger!
		$a_01_5 = {57 69 6e 64 6f 77 73 20 68 61 73 20 64 65 74 65 63 74 65 64 20 73 70 79 77 61 72 65 } //1 Windows has detected spyware
		$a_01_6 = {53 79 73 74 65 6d 20 41 6c 65 72 74 21 } //1 System Alert!
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=33
 
}