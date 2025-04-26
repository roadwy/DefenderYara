
rule Trojan_Win32_FormBook_EC_MTB{
	meta:
		description = "Trojan:Win32/FormBook.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_81_0 = {6e 56 69 61 62 6c 65 20 53 6f 6c 75 74 69 6f 6e 70 2e 70 63 72 } //3 nViable Solutionp.pcr
		$a_81_1 = {44 6f 6e 20 48 4f } //3 Don HO
		$a_81_2 = {57 41 5f 51 4d 53 49 4d } //3 WA_QMSIM
		$a_81_3 = {53 65 74 4c 61 79 65 72 65 64 57 69 6e 64 6f 77 41 74 74 72 69 62 75 74 65 73 } //3 SetLayeredWindowAttributes
		$a_81_4 = {70 73 52 75 6e 6e 69 6e 67 } //3 psRunning
		$a_81_5 = {54 61 73 6b 62 61 72 43 72 65 61 74 65 64 } //3 TaskbarCreated
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3) >=18
 
}