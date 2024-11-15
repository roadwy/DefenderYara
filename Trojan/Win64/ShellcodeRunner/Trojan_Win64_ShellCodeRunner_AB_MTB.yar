
rule Trojan_Win64_ShellCodeRunner_AB_MTB{
	meta:
		description = "Trojan:Win64/ShellCodeRunner.AB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {71 64 59 20 ef cf 79 da b8 1a ee 34 84 e7 33 2a 98 1c 78 94 73 50 62 dd 43 44 44 3a 90 63 7e 12 6f 4d 87 8b 51 32 2b db 8a 2d 8e 21 23 ef d6 7e af 07 5e 87 7f f5 48 65 18 12 b0 1e 6e 86 e0 8c 77 e0 55 8c c5 07 45 53 8d d5 8d 37 ce b5 72 54 69 98 4c e7 ac 49 ed 35 5b 17 e9 09 7d bc 56 47 c2 17 ce d2 5a 4f d0 9b c8 5f 25 91 09 b8 13 27 7e e4 82 cb 4d 4c 75 58 74 c2 82 df 7f 98 dd 84 57 f5 52 a7 ba bc 31 cf 67 25 64 28 9c 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}