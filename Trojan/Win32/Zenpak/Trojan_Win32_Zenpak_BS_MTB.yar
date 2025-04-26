
rule Trojan_Win32_Zenpak_BS_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e8 8b 4d f0 8a 14 01 8b 75 ec 88 14 06 05 01 00 00 00 8b 7d f4 39 f8 89 45 e8 75 } //3
		$a_01_1 = {77 00 61 00 73 00 71 00 77 00 68 00 65 00 72 00 65 00 69 00 6e 00 52 00 66 00 6f 00 72 00 74 00 68 00 77 00 61 00 73 00 73 00 75 00 62 00 64 00 75 00 65 00 73 00 65 00 61 00 73 00 6f 00 6e 00 73 00 } //1 wasqwhereinRforthwassubdueseasons
		$a_01_2 = {73 00 65 00 6c 00 66 00 20 00 65 00 78 00 65 00 } //1 self exe
		$a_01_3 = {50 71 49 47 5a 49 2f 65 53 65 6d 58 71 54 74 57 4e 2e 70 64 62 } //1 PqIGZI/eSemXqTtWN.pdb
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}