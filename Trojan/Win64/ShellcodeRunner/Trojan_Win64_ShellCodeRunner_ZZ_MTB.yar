
rule Trojan_Win64_ShellCodeRunner_ZZ_MTB{
	meta:
		description = "Trojan:Win64/ShellCodeRunner.ZZ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 85 c0 48 89 c3 0f 84 45 01 00 00 49 89 c4 48 89 c5 66 0f ef c0 48 01 be 80 20 00 00 49 c1 fc 15 0f 29 40 10 48 c1 fd 0c 48 89 78 08 48 c7 00 01 00 00 00 41 0f b6 c4 4c 8d 2c c6 49 8b 95 a8 20 00 00 48 85 d2 75 14 eb 4a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_ShellCodeRunner_ZZ_MTB_2{
	meta:
		description = "Trojan:Win64/ShellCodeRunner.ZZ!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 c8 49 c1 e9 04 49 f7 e2 4c 89 c8 48 89 d3 49 89 d2 49 f7 e3 48 89 f8 48 c1 eb 0b 48 c1 ea 02 48 6b d2 64 48 29 d0 48 81 f9 3f 42 0f 00 } //1
		$a_01_1 = {49 89 dc 4c 8b bc 24 b8 00 00 00 49 31 cc 4c 8b 8c 24 90 00 00 00 4c 89 e0 4c 89 de 4d 89 da 4c 31 da 4c 8b b4 24 98 00 00 00 4c 89 df 48 31 de 48 31 d0 4c 8b 84 24 90 00 00 00 49 31 ca 4d 31 ef 48 89 44 24 28 48 33 84 24 a8 00 00 00 4d 31 f9 4d 31 ce 4c 31 cb 4c 31 cf 48 89 5c 24 20 4c 89 d3 4d 31 f2 48 89 7c 24 30 48 89 cf 48 8b 4c 24 28 49 31 c5 4c 89 74 24 70 4c 8b b4 24 90 00 00 00 48 31 c7 48 89 f0 49 31 f8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}