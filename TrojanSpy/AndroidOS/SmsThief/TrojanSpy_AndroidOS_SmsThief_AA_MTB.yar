
rule TrojanSpy_AndroidOS_SmsThief_AA_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.AA!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 61 70 69 2f 75 70 6c 6f 61 64 73 2f 61 70 69 73 6d 73 } //1 /api/uploads/apisms
		$a_00_1 = {2f 63 6f 6d 2f 6c 6f 63 61 6c 2f 4c 6f 63 61 6c 4d 65 73 73 61 67 65 } //1 /com/local/LocalMessage
		$a_00_2 = {63 6f 6d 2f 7a 68 79 2f 68 74 74 70 2f 6f 6b 68 74 74 70 2f } //1 com/zhy/http/okhttp/
		$a_00_3 = {63 6f 6e 74 65 6e 74 3a 2f 2f 73 6d 73 2f } //1 content://sms/
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}