
rule Trojan_AndroidOS_Banker_V_MTB{
	meta:
		description = "Trojan:AndroidOS/Banker.V!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {43 4f 4d 4d 42 41 4e 4b 5f 49 53 5f 53 45 4e 54 } //01 00  COMMBANK_IS_SENT
		$a_00_1 = {63 6f 6d 2e 73 6c 65 6d 70 6f 2e 73 65 72 76 69 63 65 2e 61 63 74 69 76 69 74 69 65 73 } //01 00  com.slempo.service.activities
		$a_00_2 = {4c 49 53 54 45 4e 49 4e 47 5f 53 4d 53 5f 45 4e 41 42 4c 45 44 } //01 00  LISTENING_SMS_ENABLED
		$a_00_3 = {49 4e 54 45 52 43 45 50 54 49 4e 47 5f 49 4e 43 4f 4d 49 4e 47 5f 45 4e 41 42 4c 45 44 } //00 00  INTERCEPTING_INCOMING_ENABLED
	condition:
		any of ($a_*)
 
}