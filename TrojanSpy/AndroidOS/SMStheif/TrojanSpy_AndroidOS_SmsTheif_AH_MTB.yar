
rule TrojanSpy_AndroidOS_SmsTheif_AH_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsTheif.AH!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {2f 73 64 6b 73 6d 73 2f 73 6d 73 2f 73 6d 73 2e 64 6f } //1 /sdksms/sms/sms.do
		$a_01_1 = {2f 73 64 6b 73 61 6c 65 73 2f 73 79 6e 63 2f 67 65 74 61 6e 2e 64 6f } //1 /sdksales/sync/getan.do
		$a_01_2 = {53 6d 73 52 65 63 69 76 65 72 2d 52 65 70 6c 79 2d 68 75 69 66 75 74 61 73 6b } //1 SmsReciver-Reply-huifutask
		$a_01_3 = {53 6d 73 52 65 63 69 76 65 72 2d 55 70 6c 6f 61 64 } //1 SmsReciver-Upload
		$a_01_4 = {53 6d 73 52 65 63 69 76 65 72 2d 53 68 69 65 6c 64 2d 62 72 65 74 } //1 SmsReciver-Shield-bret
		$a_03_5 = {53 6d 73 54 61 73 6b [0-05] 64 65 6c 53 6d 73 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}