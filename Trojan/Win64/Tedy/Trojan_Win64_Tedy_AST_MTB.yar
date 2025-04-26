
rule Trojan_Win64_Tedy_AST_MTB{
	meta:
		description = "Trojan:Win64/Tedy.AST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {30 41 c2 04 84 91 f9 44 09 dd 3e 54 7b 34 18 12 07 0a ed 19 d4 10 f6 13 cc } //5
		$a_03_1 = {32 38 30 04 ee 84 98 ?? ?? ?? ?? 22 0f 32 52 db } //5
		$a_01_2 = {58 53 51 52 56 57 55 48 89 c3 48 83 eb 05 b9 58 60 ea 00 48 29 cb 50 b8 54 4b 44 00 48 01 d8 } //5
		$a_01_3 = {40 43 2b 20 e4 06 31 93 e8 83 b5 c1 88 0b 15 d0 84 3f 54 01 06 80 52 83 10 23 f8 1c 08 a6 3a 20 0c 2a } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5) >=10
 
}