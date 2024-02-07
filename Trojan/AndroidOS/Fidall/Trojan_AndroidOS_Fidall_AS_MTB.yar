
rule Trojan_AndroidOS_Fidall_AS_MTB{
	meta:
		description = "Trojan:AndroidOS/Fidall.AS!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4d 53 20 52 45 41 44 45 52 } //01 00  SMS READER
		$a_01_1 = {45 4d 41 49 4c 5f 4f 50 45 52 41 54 49 4f 4e 5f 43 4f 44 45 } //01 00  EMAIL_OPERATION_CODE
		$a_00_2 = {61 62 6f 6e 65 6e 74 2e 66 69 6e 64 61 6e 64 63 61 6c 6c 2e 63 6f 6d } //01 00  abonent.findandcall.com
		$a_01_3 = {43 41 4c 4c 5f 4c 4f 47 } //01 00  CALL_LOG
		$a_00_4 = {72 65 63 65 6e 74 5f 63 61 6c 6c 73 } //01 00  recent_calls
		$a_01_5 = {49 4e 43 4f 4d 49 4e 47 5f 43 41 4c 4c 53 5f 54 41 42 4c 45 5f 4e 41 4d 45 } //00 00  INCOMING_CALLS_TABLE_NAME
		$a_00_6 = {5d 04 00 00 5a } //8b 04 
	condition:
		any of ($a_*)
 
}