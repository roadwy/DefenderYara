
rule Backdoor_AndroidOS_Chuli_A{
	meta:
		description = "Backdoor:AndroidOS/Chuli.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 61 6e 64 72 6f 69 64 2e 70 68 70 00 } //1
		$a_01_1 = {39 39 39 2e 39 25 00 } //1
		$a_01_2 = {62 6f 6f 6b 5f 66 69 6c 65 00 } //1 潢歯晟汩e
		$a_01_3 = {68 79 70 6f 74 00 } //1 票潰t
		$a_01_4 = {36 34 2e 37 38 2e 31 36 31 2e 31 33 33 00 } //1 㐶㜮⸸㘱⸱㌱3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}