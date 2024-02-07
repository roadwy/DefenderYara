
rule Trojan_AndroidOS_Fakecalls_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Fakecalls.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 6f 5f 6c 69 73 74 65 6e 65 72 5f 6e 75 6d } //01 00  no_listener_num
		$a_01_1 = {69 6e 74 65 72 63 65 70 74 5f 61 6c 6c 5f 70 68 6f 6e 65 } //01 00  intercept_all_phone
		$a_01_2 = {69 6e 63 6f 6d 69 6e 67 5f 74 72 61 6e 73 66 65 72 } //01 00  incoming_transfer
		$a_01_3 = {72 65 63 6f 72 64 5f 74 65 6c 65 70 68 6f 6e 65 } //01 00  record_telephone
		$a_01_4 = {6b 6f 2f 73 68 69 6e 68 61 6e 73 61 76 69 6e 67 73 2f 70 68 6f 6e 65 } //00 00  ko/shinhansavings/phone
	condition:
		any of ($a_*)
 
}