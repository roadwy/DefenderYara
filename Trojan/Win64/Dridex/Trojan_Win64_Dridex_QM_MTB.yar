
rule Trojan_Win64_Dridex_QM_MTB{
	meta:
		description = "Trojan:Win64/Dridex.QM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_81_0 = {72 72 70 69 6f 64 65 2e 70 64 62 } //3 rrpiode.pdb
		$a_81_1 = {6f 6e 75 70 6b 72 65 61 73 6f 6e 69 6e 67 43 68 72 6f 6d 65 32 52 4c 5a 63 49 6e 74 65 72 6e 65 74 32 30 30 38 2e 32 38 } //3 onupkreasoningChrome2RLZcInternet2008.28
		$a_81_2 = {49 63 6d 70 53 65 6e 64 45 63 68 6f 32 } //3 IcmpSendEcho2
		$a_81_3 = {62 6a 61 6b 65 74 75 63 6b 65 72 4a 69 6e 66 72 6f 6d 7a 47 } //3 bjaketuckerJinfromzG
		$a_81_4 = {74 74 59 36 56 70 65 6f 76 74 64 75 73 65 } //3 ttY6Vpeovtduse
		$a_81_5 = {62 65 41 62 69 67 64 69 63 6b 62 65 65 6e 55 78 73 70 65 6c 6c 69 6e 67 } //3 beAbigdickbeenUxspelling
		$a_81_6 = {62 69 74 74 6f 34 49 6e 63 6f 67 6e 69 74 6f 49 4b 69 6e 66 } //3 bitto4IncognitoIKinf
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}