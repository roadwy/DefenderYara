
rule Trojan_Win64_Cobalt_DF_MTB{
	meta:
		description = "Trojan:Win64/Cobalt.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_00_0 = {48 89 4c 24 10 48 8b 54 cc 38 48 83 c2 d0 48 f7 da 48 83 fa 40 48 19 f6 48 89 d1 bf 01 00 00 00 48 d3 e7 48 21 f7 48 89 7c 24 18 } //10
		$a_81_1 = {71 4b 67 75 44 69 64 } //3 qKguDid
		$a_81_2 = {43 4c 52 57 72 61 70 70 65 72 } //3 CLRWrapper
		$a_81_3 = {61 70 70 44 6f 6d 61 69 6e 2e 4c 6f 61 64 5f 33 62 61 64 } //3 appDomain.Load_3bad
	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3) >=19
 
}