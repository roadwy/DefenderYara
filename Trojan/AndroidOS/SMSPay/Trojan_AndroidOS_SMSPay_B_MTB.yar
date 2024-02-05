
rule Trojan_AndroidOS_SMSPay_B_MTB{
	meta:
		description = "Trojan:AndroidOS/SMSPay.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 76 65 6e 69 73 6f 2f 6d 74 72 75 73 73 6c 69 62 61 6e 64 } //01 00 
		$a_01_1 = {64 65 76 65 6c 6f 70 65 72 50 61 79 6c 6f 61 64 } //01 00 
		$a_01_2 = {4d 54 4c 69 62 53 4d 53 52 65 63 65 69 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}