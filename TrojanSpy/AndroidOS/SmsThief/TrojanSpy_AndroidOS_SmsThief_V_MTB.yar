
rule TrojanSpy_AndroidOS_SmsThief_V_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.V!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_00_0 = {74 72 61 63 6b 49 6e 73 74 61 6c 6c } //1 trackInstall
		$a_00_1 = {75 70 6c 6f 61 64 6d 73 67 } //1 uploadmsg
		$a_00_2 = {53 6d 73 49 6e 66 6f } //1 SmsInfo
		$a_00_3 = {6d 6f 6e 73 65 72 76 65 72 } //1 monserver
		$a_00_4 = {75 70 6c 6f 61 64 5f 73 63 72 65 65 6e 73 68 6f 74 } //1 upload_screenshot
		$a_00_5 = {67 65 74 54 61 73 6b 44 65 74 61 69 6c 49 6e 66 6f } //1 getTaskDetailInfo
		$a_00_6 = {67 65 74 43 6f 75 70 6f 6e 48 69 73 74 6f 72 79 4d 6f 72 65 44 61 74 61 } //1 getCouponHistoryMoreData
		$a_00_7 = {67 65 74 46 69 73 74 46 6f 72 77 61 72 64 49 6e 66 6f } //1 getFistForwardInfo
		$a_00_8 = {46 6f 72 77 61 72 64 44 65 74 61 69 6c 41 63 74 69 76 69 74 79 } //1 ForwardDetailActivity
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=7
 
}