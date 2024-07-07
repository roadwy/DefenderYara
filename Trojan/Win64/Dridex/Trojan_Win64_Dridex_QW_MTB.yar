
rule Trojan_Win64_Dridex_QW_MTB{
	meta:
		description = "Trojan:Win64/Dridex.QW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 45 d0 8a 08 8b 55 94 89 55 fc 48 8b 45 c0 49 89 c0 49 83 c0 01 4c 89 45 c0 44 8b 4d 98 41 81 c1 5e 0b 00 00 44 89 4d fc 88 08 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Trojan_Win64_Dridex_QW_MTB_2{
	meta:
		description = "Trojan:Win64/Dridex.QW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_00_0 = {44 89 8c 24 e0 02 00 00 8a 94 24 df 02 00 00 44 8a 94 24 4f 02 00 00 80 c2 2d 88 84 24 f5 02 00 00 } //10
		$a_81_1 = {45 78 70 6c 6f 72 65 72 5f 53 65 72 76 65 72 } //3 Explorer_Server
		$a_81_2 = {74 65 73 74 73 76 69 63 74 6f 72 69 61 34 62 65 6e 63 68 6d 61 72 6b 73 2c 73 75 62 6d 69 73 73 69 6f 6e 73 } //3 testsvictoria4benchmarks,submissions
		$a_81_3 = {43 68 72 6f 6d 65 31 37 61 73 6b 73 5a 49 72 65 6d 6f 76 65 64 2e 77 61 73 79 7a 41 } //3 Chrome17asksZIremoved.wasyzA
	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3) >=19
 
}