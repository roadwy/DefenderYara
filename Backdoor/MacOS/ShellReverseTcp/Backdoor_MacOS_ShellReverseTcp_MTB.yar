
rule Backdoor_MacOS_ShellReverseTcp_MTB{
	meta:
		description = "Backdoor:MacOS/ShellReverseTcp!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {5a c0 a0 e3 0a 00 a0 e1 05 10 a0 e1 80 00 00 ef 01 50 45 e2 00 00 55 e3 f8 ff ff aa 00 00 a0 e3 00 10 a0 e3 7e c0 a0 e3 80 00 00 ef 05 50 45 e0 0d 60 a0 e1 20 d0 4d e2 14 00 8f e2 00 00 86 e4 04 50 86 e5 06 10 a0 e1 00 20 a0 e3 3b c0 a0 e3 80 00 00 ef } //02 00 
		$a_00_1 = {0a 00 a0 e1 0e 10 a0 e1 10 20 a0 e3 62 c0 a0 e3 80 00 00 ef 02 50 a0 e3 } //01 00 
		$a_00_2 = {2f 62 69 6e 2f 73 68 } //01 00  /bin/sh
		$a_00_3 = {73 68 65 6c 6c 63 6f 64 65 } //00 00  shellcode
	condition:
		any of ($a_*)
 
}