
rule Trojan_AndroidOS_SendSMS_A_MTB{
	meta:
		description = "Trojan:AndroidOS/SendSMS.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 65 74 53 4d 53 56 61 6c 55 52 4c } //01 00 
		$a_00_1 = {63 6f 6e 66 69 72 6d 5f 73 65 6e 64 5f 73 6d 73 5f 6d 73 67 } //01 00 
		$a_00_2 = {50 6c 65 61 73 65 20 65 6e 74 65 72 20 62 6f 74 68 20 70 68 6f 6e 65 20 6e 75 6d 62 65 72 20 61 6e 64 20 6d 65 73 73 61 67 65 } //01 00 
		$a_00_3 = {53 68 6f 72 74 63 75 74 32 41 70 6b 41 63 74 69 76 69 74 79 } //01 00 
		$a_00_4 = {73 6d 73 5f 73 65 72 76 69 63 65 2f 62 6f 69 62 61 69 74 61 79 2f } //00 00 
	condition:
		any of ($a_*)
 
}