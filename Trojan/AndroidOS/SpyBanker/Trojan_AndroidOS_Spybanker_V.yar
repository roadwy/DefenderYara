
rule Trojan_AndroidOS_Spybanker_V{
	meta:
		description = "Trojan:AndroidOS/Spybanker.V,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {4c 49 53 54 45 4e 49 4e 47 5f 53 4d 53 5f 45 4e 41 42 4c 45 44 } //2 LISTENING_SMS_ENABLED
		$a_01_1 = {49 4e 54 45 52 43 45 50 54 49 4e 47 5f 49 4e 43 4f 4d 49 4e 47 5f 45 4e 41 42 4c 45 44 } //2 INTERCEPTING_INCOMING_ENABLED
		$a_01_2 = {49 4e 54 45 52 43 45 50 54 45 44 5f 4e 55 4d 53 } //2 INTERCEPTED_NUMS
		$a_01_3 = {49 4e 49 54 49 41 4c 5f 44 41 54 41 5f 49 53 5f 53 45 4e 54 } //2 INITIAL_DATA_IS_SENT
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=6
 
}