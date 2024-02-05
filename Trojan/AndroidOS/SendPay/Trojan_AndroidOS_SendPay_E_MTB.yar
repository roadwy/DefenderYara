
rule Trojan_AndroidOS_SendPay_E_MTB{
	meta:
		description = "Trojan:AndroidOS/SendPay.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 68 65 72 6f 69 74 2f 74 7a 75 77 65 69 2f 6c 69 74 65 2f 4d 65 73 73 61 67 65 41 63 74 69 76 69 74 79 } //01 00 
		$a_01_1 = {63 6e 2f 6d 6f 62 69 6c 65 2f 43 6c 69 65 6e 74 2f 61 70 6b 2f 69 6d 6f 6e 65 79 } //01 00 
		$a_01_2 = {73 65 6e 64 4d 75 6c 74 69 70 61 72 74 54 65 78 74 4d 65 73 73 61 67 65 } //01 00 
		$a_01_3 = {6d 4c 75 63 6b 4d 65 6e 53 68 6f 77 } //01 00 
		$a_01_4 = {74 65 78 74 2f 78 2d 73 6d 73 2d 6e 75 6d 62 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}