
rule Trojan_Win32_Runner_RP_MTB{
	meta:
		description = "Trojan:Win32/Runner.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 4d 00 69 00 72 00 63 00 5c 00 2a 00 2e 00 2a 00 } //1 C:\Mirc\*.*
		$a_01_1 = {75 6e 6b 6e 6f 77 6e 64 6c 6c 2e 70 64 62 } //1 unknowndll.pdb
		$a_01_2 = {4e 61 6d 65 20 53 65 74 75 70 3a 20 49 6e 73 74 61 6c 6c 69 6e 67 } //1 Name Setup: Installing
		$a_01_3 = {4e 61 6d 65 20 53 65 74 75 70 3a 20 43 6f 6d 70 6c 65 74 65 64 } //1 Name Setup: Completed
		$a_01_4 = {45 00 78 00 65 00 63 00 53 00 68 00 65 00 6c 00 6c 00 3a 00 } //1 ExecShell:
		$a_01_5 = {4e 75 6c 6c 73 6f 66 74 49 6e 73 74 } //1 NullsoftInst
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}