
rule Trojan_AndroidOS_Spypaidy_A{
	meta:
		description = "Trojan:AndroidOS/Spypaidy.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 72 69 63 68 73 6a 65 73 6f 6e 2e 6b 6f 74 6c 69 6e 2e 73 6d 73 2e 55 70 6c 6f 61 64 43 6f 6e 74 61 63 74 73 24 43 6f 6d 70 61 6e 69 6f 6e 24 64 6f 55 70 6c 6f 61 64 24 31 } //01 00  com.richsjeson.kotlin.sms.UploadContacts$Companion$doUpload$1
		$a_01_1 = {77 69 66 69 50 77 64 } //01 00  wifiPwd
		$a_01_2 = {73 65 6e 64 53 6d 73 53 69 6c 65 6e 74 } //01 00  sendSmsSilent
		$a_01_3 = {68 69 64 65 4e 6f 74 69 66 69 63 61 74 69 6f 6e 41 66 74 65 72 4f } //00 00  hideNotificationAfterO
	condition:
		any of ($a_*)
 
}