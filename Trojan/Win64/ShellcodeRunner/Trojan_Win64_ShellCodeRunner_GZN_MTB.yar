
rule Trojan_Win64_ShellCodeRunner_GZN_MTB{
	meta:
		description = "Trojan:Win64/ShellCodeRunner.GZN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 44 24 30 4c c6 44 24 31 6f c6 44 24 32 61 c6 44 24 33 64 c6 44 24 34 4c c6 44 24 35 69 c6 44 24 36 62 c6 44 24 37 72 c6 44 24 38 61 c6 44 24 39 72 c6 44 24 3a 79 c6 44 24 3b 41 c6 44 24 3c 00 c6 44 24 40 47 c6 44 24 41 65 c6 44 24 42 74 c6 44 24 43 50 c6 44 24 44 72 c6 44 24 45 6f c6 44 24 46 63 c6 44 24 47 41 c6 44 24 48 64 c6 44 24 49 64 c6 44 24 4a 72 c6 44 24 4b 65 c6 44 24 4c 73 c6 44 24 4d 73 c6 44 24 4e 00 c6 44 24 28 57 c6 44 24 29 69 c6 44 24 2a 6e c6 44 24 2b 45 c6 44 24 2c 78 c6 44 24 2d 65 c6 44 24 2e 63 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}