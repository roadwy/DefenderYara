
rule Trojan_Win64_ShellCodeRunner_AB_MTB{
	meta:
		description = "Trojan:Win64/ShellCodeRunner.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 89 44 24 7c c6 84 24 80 05 00 00 d7 c6 84 24 81 05 00 00 03 c6 84 24 82 05 00 00 c2 c6 84 24 83 05 00 00 bd c6 84 24 84 05 00 00 2b c6 84 24 85 05 00 00 f8 c6 84 24 86 05 00 00 5f c6 84 24 87 05 00 00 c1 c6 84 24 88 05 00 00 25 c6 84 24 89 05 00 00 07 c6 84 24 8a 05 00 00 63 c6 84 24 8b 05 00 00 b9 c6 84 24 8c 05 00 00 ec c7 84 24 74 06 00 00 03 00 00 00 c7 84 24 e8 01 00 00 70 0b 00 00 c7 84 24 20 07 00 00 00 00 00 00 8b 84 24 74 06 00 00 89 84 24 ec 08 00 00 8b 84 24 74 06 00 00 ff c8 } //6
		$a_01_1 = {89 84 24 74 06 00 00 83 bc 24 ec 08 00 00 00 7e 50 8b 84 24 e8 01 00 00 6b c0 0b 25 14 b2 00 00 89 84 24 20 07 00 00 8b 84 24 e8 01 00 00 d1 e8 8b 8c 24 20 07 00 00 33 c1 89 84 24 e8 01 00 00 8b 84 24 e8 01 00 00 83 e0 78 85 c0 75 11 8b 84 24 e8 01 00 00 83 c8 7c 89 84 24 e8 01 00 00 eb 88 } //6
	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*6) >=12
 
}
rule Trojan_Win64_ShellCodeRunner_AB_MTB_2{
	meta:
		description = "Trojan:Win64/ShellCodeRunner.AB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {71 64 59 20 ef cf 79 da b8 1a ee 34 84 e7 33 2a 98 1c 78 94 73 50 62 dd 43 44 44 3a 90 63 7e 12 6f 4d 87 8b 51 32 2b db 8a 2d 8e 21 23 ef d6 7e af 07 5e 87 7f f5 48 65 18 12 b0 1e 6e 86 e0 8c 77 e0 55 8c c5 07 45 53 8d d5 8d 37 ce b5 72 54 69 98 4c e7 ac 49 ed 35 5b 17 e9 09 7d bc 56 47 c2 17 ce d2 5a 4f d0 9b c8 5f 25 91 09 b8 13 27 7e e4 82 cb 4d 4c 75 58 74 c2 82 df 7f 98 dd 84 57 f5 52 a7 ba bc 31 cf 67 25 64 28 9c 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}