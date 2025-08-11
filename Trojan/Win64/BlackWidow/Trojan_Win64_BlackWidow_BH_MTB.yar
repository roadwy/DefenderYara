
rule Trojan_Win64_BlackWidow_BH_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 89 c8 c5 e5 71 f3 07 c4 e3 fd 00 f6 d8 c4 e3 fd 00 ff d8 } //1
		$a_01_1 = {45 8a 14 10 } //1
		$a_01_2 = {4c 8b 45 f8 } //1
		$a_01_3 = {57 32 42 78 35 24 4b 29 55 66 77 51 75 6b 2b 44 74 5e 4c 42 } //2 W2Bx5$K)UfwQuk+Dt^LB
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=5
 
}