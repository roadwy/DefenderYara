
rule Trojan_Win64_ShellCodeExec_DA_MTB{
	meta:
		description = "Trojan:Win64/ShellCodeExec.DA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4b 8b 8c eb 00 e3 03 00 49 03 ce 42 8a 04 36 42 88 44 f9 3e ff c7 49 ff c6 48 63 c7 48 3b c2 7c df } //1
		$a_01_1 = {48 ff c6 48 89 7c 24 38 48 89 7c 24 30 c7 44 24 28 05 00 00 00 48 8d 45 0f 48 89 44 24 20 45 8b cc 4c 8d 45 93 33 d2 8b 4d b7 e8 73 2e 00 00 44 8b f0 85 c0 0f 84 1b 01 00 00 48 89 7c 24 20 4c 8d 4d 97 44 8b c0 48 8d 55 0f 4c 8b 65 e7 49 8b cc } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}