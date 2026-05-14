
rule Trojan_Linux_Mirai_HAF_MTB{
	meta:
		description = "Trojan:Linux/Mirai.HAF!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,2d 00 2d 00 04 00 00 "
		
	strings :
		$a_01_0 = {0e 34 b4 58 df 38 b5 79 c9 53 cd 19 cc 67 c8 88 45 f8 c8 ea 08 c2 10 f9 ee df 86 f9 e0 bb f8 f2 } //5
		$a_01_1 = {12 ae cb 89 4d 9d 65 ac 6d 2f 1e 73 77 86 51 11 } //12
		$a_01_2 = {74 7a 30 28 07 9a 93 dd a9 25 5c 62 53 47 fd ba } //15
		$a_01_3 = {35 39 1e 59 7f 4c 62 51 e3 0a e2 75 3e 64 db d3 } //13
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*12+(#a_01_2  & 1)*15+(#a_01_3  & 1)*13) >=45
 
}