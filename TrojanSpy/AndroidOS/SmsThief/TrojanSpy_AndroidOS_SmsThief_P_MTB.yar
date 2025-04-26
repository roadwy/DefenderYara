
rule TrojanSpy_AndroidOS_SmsThief_P_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.P!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_00_0 = {4e 6f 74 69 66 69 63 61 74 69 6f 6e 4d 6f 6e 69 74 6f 72 53 65 72 76 69 63 65 } //1 NotificationMonitorService
		$a_00_1 = {2f 61 70 69 2f 75 70 6c 6f 61 64 73 2f 73 69 6d 73 61 76 65 } //1 /api/uploads/simsave
		$a_00_2 = {63 6f 6c 6c 65 63 74 44 65 76 69 63 65 49 6e 66 6f } //1 collectDeviceInfo
		$a_00_3 = {75 70 6c 6f 61 64 53 6d 73 } //1 uploadSms
		$a_00_4 = {67 65 74 41 6c 6c 50 68 6f 74 6f 49 6e 66 6f } //1 getAllPhotoInfo
		$a_00_5 = {73 6d 73 49 6e 50 68 6f 6e 65 } //1 smsInPhone
		$a_00_6 = {75 70 6c 6f 61 64 73 2f 70 68 6f 74 6f 73 61 76 65 } //1 uploads/photosave
		$a_00_7 = {2d 64 65 6c 65 74 65 53 4d 53 } //1 -deleteSMS
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=7
 
}