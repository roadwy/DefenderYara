
rule Trojan_AndroidOS_Devixor_AMTB{
	meta:
		description = "Trojan:AndroidOS/Devixor!AMTB,SIGNATURE_TYPE_DEXHSTR_EXT,11 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {69 72 2e 64 65 76 69 78 6f 72 2e 61 70 70 } //10 ir.devixor.app
		$a_81_1 = {66 6f 72 65 67 72 6f 75 6e 64 53 65 72 76 69 63 65 32 2e 65 30 28 61 72 72 61 79 4c 69 73 74 2c 20 22 63 61 6d 65 72 61 5f } //1 foregroundService2.e0(arrayList, "camera_
		$a_81_2 = {46 43 4d 5f 53 45 52 56 49 43 45 } //1 FCM_SERVICE
		$a_81_3 = {72 65 63 65 69 76 65 5f 75 72 6c } //1 receive_url
		$a_81_4 = {53 45 52 56 49 43 45 5f 47 45 54 5f 43 4d 44 } //1 SERVICE_GET_CMD
		$a_81_5 = {74 79 70 65 3d 55 50 4c 4f 41 44 5f 49 4d 41 47 45 5f 5a 49 50 26 70 6f 72 74 3d } //1 type=UPLOAD_IMAGE_ZIP&port=
		$a_81_6 = {47 45 54 5f 53 43 52 45 45 4e 53 48 4f 54 53 } //1 GET_SCREENSHOTS
		$a_81_7 = {47 45 54 5f 53 49 4d 5f 53 4d 53 } //1 GET_SIM_SMS
		$a_81_8 = {47 45 54 5f 55 53 53 44 5f 49 4e 46 4f } //1 GET_USSD_INFO
		$a_81_9 = {73 6d 73 5f 61 6c 65 72 74 } //1 sms_alert
		$a_81_10 = {52 65 63 65 69 76 65 64 20 63 6f 6d 6d 61 6e 64 3a } //1 Received command:
		$a_81_11 = {45 6d 75 6c 61 74 6f 72 20 64 65 74 65 63 74 65 64 } //1 Emulator detected
		$a_81_12 = {44 65 62 75 67 67 65 72 20 64 65 74 65 63 74 65 64 20 64 75 72 69 6e 67 20 72 75 6e 74 69 6d 65 } //1 Debugger detected during runtime
	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1) >=13
 
}