
rule Trojan_Win32_NjRat_NEL_MTB{
	meta:
		description = "Trojan:Win32/NjRat.NEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_01_0 = {6a 00 6d 00 73 00 63 00 74 00 6c 00 73 00 5f 00 70 00 72 00 6f 00 67 00 72 00 65 00 73 00 73 00 33 00 32 00 } //4 jmsctls_progress32
		$a_01_1 = {77 00 69 00 6e 00 72 00 61 00 72 00 73 00 66 00 78 00 6d 00 61 00 70 00 70 00 69 00 6e 00 67 00 66 00 69 00 6c 00 65 00 2e 00 74 00 6d 00 70 00 } //4 winrarsfxmappingfile.tmp
		$a_01_2 = {6d 53 47 35 4d 30 6c 6c 52 71 } //3 mSG5M0llRq
		$a_01_3 = {6e 6d 75 6a 75 75 6a 6a 69 69 69 69 32 78 69 6a 69 6a 6a 6a 6a 6a 6a 6d 6e 6e } //3 nmujuujjiiii2xijijjjjjjmnn
		$a_01_4 = {5f 61 62 77 77 77 77 6f 77 77 77 77 77 77 77 77 77 77 77 77 77 77 77 77 77 62 61 70 } //3 _abwwwwowwwwwwwwwwwwwwwwwbap
		$a_01_5 = {49 44 43 5f 4f 57 52 41 53 4b 52 45 50 4c 41 43 45 } //3 IDC_OWRASKREPLACE
		$a_01_6 = {73 66 78 5c 62 75 69 6c 64 } //1 sfx\build
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3+(#a_01_6  & 1)*1) >=21
 
}