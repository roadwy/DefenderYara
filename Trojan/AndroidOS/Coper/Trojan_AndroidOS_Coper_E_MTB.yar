
rule Trojan_AndroidOS_Coper_E_MTB{
	meta:
		description = "Trojan:AndroidOS/Coper.E!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 b0 be b5 05 af bb 60 0a 4b 7b 44 1c 68 23 68 02 93 07 f1 08 03 05 68 01 93 d5 f8 cc 51 a8 47 21 68 02 9a 91 42 02 bf bd e8 be 40 01 b0 70 47 03 f0 44 ee } //1
		$a_01_1 = {a7 f1 45 03 30 46 a0 47 02 46 30 46 29 46 02 f0 c4 ed 04 46 30 68 a7 f1 52 01 82 69 30 46 90 47 01 46 30 68 a7 f1 5a 02 a7 f1 6f 03 d0 f8 84 50 30 46 a8 47 02 46 30 46 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}