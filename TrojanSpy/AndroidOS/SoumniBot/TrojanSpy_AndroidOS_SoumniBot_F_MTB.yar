
rule TrojanSpy_AndroidOS_SoumniBot_F_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SoumniBot.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 61 6c 70 72 61 73 2f 6d 61 6e 61 67 65 72 } //1 com/alpras/manager
		$a_01_1 = {50 48 4f 4e 45 5f 53 45 4e 44 5f 53 4d 53 5f 44 41 54 45 } //1 PHONE_SEND_SMS_DATE
		$a_01_2 = {50 48 4f 4e 45 5f 44 49 46 46 5f 57 49 54 48 5f 53 45 52 56 45 52 } //1 PHONE_DIFF_WITH_SERVER
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}