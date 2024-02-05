
rule Trojan_AndroidOS_SmsSend_B_MTB{
	meta:
		description = "Trojan:AndroidOS/SmsSend.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 74 6f 6d 6b 6f 6f 6c 65 2f 73 6d 73 70 69 6e 67 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 55 72 6c 45 76 65 6e 74 6f } //01 00 
		$a_01_2 = {48 69 6c 6f 4c 65 65 53 4d 53 } //01 00 
		$a_01_3 = {52 65 64 69 72 69 6a 6f 53 4d 53 50 69 6e 67 } //01 00 
		$a_01_4 = {4c 65 65 72 53 6d 73 } //00 00 
	condition:
		any of ($a_*)
 
}