
rule Trojan_Win64_ShellcodeRunner_MKC_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.MKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 44 24 78 4d 8d 24 82 45 8b 24 24 49 01 d4 4d 8d 2c 43 45 0f b7 6d 00 4f 8d 2c a9 45 8b 6d 00 49 01 d5 4c 89 6c 24 60 } //15
		$a_01_1 = {c7 44 24 1e 3a 5c 77 69 48 ba 6e 64 6f 77 73 5c 73 79 48 89 54 24 22 48 ba 73 74 65 6d 33 32 5c 6e 48 89 54 24 2a 48 ba 74 64 6c 6c 2e 64 6c 6c 48 89 54 24 32 } //10
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10) >=25
 
}