
rule Trojan_Win32_Farfli_MK_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4b 00 4b 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b d0 c1 ea 1d 8b f8 c1 ef 1e 83 e2 01 83 e7 01 8d 14 57 8b f8 c1 ef 1f 8d 14 57 8b 14 95 a4 9d 43 } //25
		$a_81_1 = {5b 73 31 63 72 6f 6c 6c 6c 6f 31 63 6b 5d } //20 [s1crolllo1ck]
		$a_81_2 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 } //15 SeShutdownPrivilege
		$a_81_3 = {41 70 61 74 65 44 4e 53 } //10 ApateDNS
		$a_81_4 = {54 43 50 45 79 65 } //5 TCPEye
	condition:
		((#a_01_0  & 1)*25+(#a_81_1  & 1)*20+(#a_81_2  & 1)*15+(#a_81_3  & 1)*10+(#a_81_4  & 1)*5) >=75
 
}