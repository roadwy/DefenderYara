
rule Trojan_AndroidOS_Coper_D_MTB{
	meta:
		description = "Trojan:AndroidOS/Coper.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {d0 f8 84 60 20 d0 2e aa a7 f1 41 03 20 46 b0 47 02 46 20 46 29 46 01 f0 b6 ef 05 46 20 68 a7 f1 4e 01 82 69 20 46 90 47 01 46 20 68 a7 f1 56 02 a7 f1 6b 03 d0 f8 84 60 20 46 b0 47 02 46 20 46 29 46 } //1
		$a_01_1 = {29 46 01 f0 56 ee 20 e0 a7 f1 7e 02 a7 f1 a5 03 20 46 a8 47 02 46 20 46 31 46 01 f0 4a ee 05 46 20 68 82 69 4a a9 20 46 90 47 01 46 20 68 a7 f1 e3 03 d0 f8 78 61 48 aa 20 46 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}