
rule TrojanSpy_AndroidOS_InfoStealer_H_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/InfoStealer.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 73 61 6b 75 2f 61 70 70 2f 70 6f 3b } //01 00  Lcom/saku/app/po;
		$a_00_1 = {2f 61 70 69 2f 7a 68 75 61 6e 5f 62 6f } //01 00  /api/zhuan_bo
		$a_00_2 = {63 61 6c 6c 44 75 72 61 74 69 6f 6e 53 74 72 } //01 00  callDurationStr
		$a_01_3 = {73 6d 73 5f 73 74 72 } //00 00  sms_str
		$a_00_4 = {be 99 00 } //00 0a 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_AndroidOS_InfoStealer_H_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/InfoStealer.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0a 00 0a 00 07 00 00 05 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 74 65 73 74 2f 75 70 6c 6f 61 64 63 6f 6e 74 61 63 74 } //02 00  Lcom/test/uploadcontact
		$a_00_1 = {63 6f 6e 74 65 6e 74 3a 2f 2f 73 6d 73 2f 72 61 77 } //01 00  content://sms/raw
		$a_00_2 = {68 69 64 65 41 70 70 } //01 00  hideApp
		$a_00_3 = {61 64 64 72 65 73 73 4c 69 73 74 } //01 00  addressList
		$a_00_4 = {53 4d 53 4f 62 73 65 72 76 65 72 } //01 00  SMSObserver
		$a_00_5 = {4d 53 47 55 70 6c 6f 61 64 65 64 } //01 00  MSGUploaded
		$a_00_6 = {2f 4a 59 53 79 73 74 65 6d 2f 72 65 73 74 49 6e 74 2f 63 6f 6c 6c 65 63 74 2f 70 6f 73 74 44 61 74 61 } //00 00  /JYSystem/restInt/collect/postData
		$a_00_7 = {5d 04 00 00 c7 64 04 } //80 5c 
	condition:
		any of ($a_*)
 
}