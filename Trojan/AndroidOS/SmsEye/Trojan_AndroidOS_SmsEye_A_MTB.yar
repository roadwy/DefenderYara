
rule Trojan_AndroidOS_SmsEye_A_MTB{
	meta:
		description = "Trojan:AndroidOS/SmsEye.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6d 73 45 79 65 54 6f 6f 6c 73 } //01 00 
		$a_01_1 = {54 65 6c 65 67 72 61 6d 42 6f 74 } //01 00 
		$a_01_2 = {61 62 79 73 73 61 6c 61 72 6d 79 2f 73 6d 73 65 79 65 } //01 00 
		$a_01_3 = {73 6d 73 45 79 65 44 61 74 61 } //01 00 
		$a_01_4 = {53 6d 73 45 79 65 57 65 62 76 69 65 77 4b 74 } //00 00 
	condition:
		any of ($a_*)
 
}