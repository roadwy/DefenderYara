
rule TrojanSpy_AndroidOS_SMSSpy_L_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SMSSpy.L!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6e 65 74 2e 74 72 69 63 65 73 2e } //1 net.trices.
		$a_01_1 = {53 6d 73 4c 69 73 74 6e 65 72 } //1 SmsListner
		$a_01_2 = {69 6e 74 65 6e 74 2e 65 78 74 72 61 73 21 21 } //1 intent.extras!!
		$a_01_3 = {52 65 63 65 69 76 65 64 20 53 4d 53 20 66 72 6f 6d } //1 Received SMS from
		$a_01_4 = {52 45 51 5f 43 4f 44 45 5f 50 45 52 4d 49 53 53 49 4f 4e 5f 52 45 41 44 5f 53 4d 53 } //1 REQ_CODE_PERMISSION_READ_SMS
		$a_01_5 = {52 45 51 5f 43 4f 44 45 5f 50 45 52 4d 49 53 53 49 4f 4e 5f 52 45 43 45 49 56 45 5f 53 4d 53 } //1 REQ_CODE_PERMISSION_RECEIVE_SMS
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}