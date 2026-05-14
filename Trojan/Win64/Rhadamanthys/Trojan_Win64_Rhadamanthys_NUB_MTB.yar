
rule Trojan_Win64_Rhadamanthys_NUB_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NUB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 b8 b7 98 63 bb a6 ba 79 01 4c 89 c2 48 c1 ea 04 48 f7 e2 48 d1 ea 48 69 c2 b0 15 00 00 4c 89 c2 48 29 c2 48 83 fa 07 } //3
		$a_01_1 = {48 ba 62 00 63 00 72 00 79 00 c7 44 24 30 14 00 16 00 48 89 54 24 40 4c 8d 44 24 30 48 ba 70 00 74 00 2e 00 64 00 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}