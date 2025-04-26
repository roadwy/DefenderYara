
rule Trojan_BAT_Bladabindi_NK_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {0b 08 17 58 0c 08 06 8e 69 17 59 fe 02 16 fe 01 13 04 11 04 2d dc } //5
		$a_81_1 = {4e 65 72 6f 20 6c 61 69 74 5c 6f 62 6a 5c 44 65 62 75 67 5c 4e 65 72 6f 20 6c 61 69 74 2e 70 64 62 } //1 Nero lait\obj\Debug\Nero lait.pdb
		$a_81_2 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_4 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_01_0  & 1)*5+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=9
 
}