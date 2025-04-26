
rule Trojan_Win64_T1563_RemoteServiceSessionHijacking_A{
	meta:
		description = "Trojan:Win64/T1563_RemoteServiceSessionHijacking.A,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {74 00 73 00 3a 00 3a 00 72 00 65 00 6d 00 6f 00 74 00 65 00 } //10 ts::remote
		$a_01_1 = {74 00 73 00 3a 00 3a 00 73 00 65 00 73 00 73 00 69 00 6f 00 6e 00 73 00 } //10 ts::sessions
		$a_01_2 = {76 00 61 00 75 00 6c 00 74 00 3a 00 3a 00 63 00 72 00 65 00 64 00 } //10 vault::cred
		$a_01_3 = {76 00 61 00 75 00 6c 00 74 00 3a 00 3a 00 6c 00 69 00 73 00 74 00 } //10 vault::list
		$a_01_4 = {73 00 65 00 6b 00 75 00 72 00 6c 00 73 00 61 00 3a 00 3a 00 63 00 6c 00 6f 00 75 00 64 00 61 00 70 00 } //10 sekurlsa::cloudap
		$a_01_5 = {73 00 65 00 6b 00 75 00 72 00 6c 00 73 00 61 00 3a 00 3a 00 63 00 72 00 65 00 64 00 6d 00 61 00 6e 00 } //10 sekurlsa::credman
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10) >=10
 
}