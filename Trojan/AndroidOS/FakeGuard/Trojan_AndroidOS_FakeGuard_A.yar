
rule Trojan_AndroidOS_FakeGuard_A{
	meta:
		description = "Trojan:AndroidOS/FakeGuard.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 65 6e 64 4d 65 73 73 61 67 65 28 29 20 43 6f 6e 6e 65 63 74 20 45 72 72 6f 72 21 21 } //1 SendMessage() Connect Error!!
		$a_01_1 = {53 4d 53 20 46 72 6f 6d 31 3a } //1 SMS From1:
		$a_01_2 = {52 65 73 65 74 69 6e 67 3a } //1 Reseting:
		$a_01_3 = {53 70 61 6d 42 6c 6f 63 6b 65 72 } //1 SpamBlocker
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}