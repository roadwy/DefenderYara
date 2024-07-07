
rule Backdoor_Win64_Mozaakai_MBK_MTB{
	meta:
		description = "Backdoor:Win64/Mozaakai.MBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {89 ee 89 e8 35 90 02 04 21 e8 f7 d5 81 e5 90 02 04 21 fe 09 ee 31 fe 89 f5 21 c5 31 f0 09 e8 89 84 90 02 05 4c 29 c3 4c 29 cb 4c 01 c3 4c 01 cb 48 ff c3 48 ff c1 48 83 f9 90 02 01 75 90 00 } //1
		$a_03_1 = {89 f2 89 f7 81 f7 90 02 04 21 f7 31 de 81 e6 90 02 04 44 21 fa 09 f2 44 31 fa 89 d6 21 fe 31 d7 09 f7 89 fa 31 da 81 e2 90 02 04 81 e7 90 02 04 09 d7 81 f7 90 02 04 89 7c 90 02 02 4c 29 e9 4c 29 f1 4c 01 e9 4c 01 f1 48 ff c1 48 ff c0 48 83 f8 90 02 01 75 90 00 } //1
		$a_03_2 = {31 da 89 d7 21 ef 09 ea 31 fa 89 d7 31 df 81 e2 90 02 04 81 e7 90 02 04 09 d7 81 f7 90 02 04 89 7c 90 02 02 48 ff c1 48 ff c0 48 83 f8 90 02 01 75 90 00 } //1
		$a_03_3 = {89 fd f7 d5 81 e5 90 02 04 89 fe 21 c6 09 ee 31 c6 81 e7 90 02 04 09 f7 89 90 02 06 48 ff c1 48 83 f9 90 02 01 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=2
 
}