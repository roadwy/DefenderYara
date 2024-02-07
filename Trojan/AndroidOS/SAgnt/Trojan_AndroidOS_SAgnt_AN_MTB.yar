
rule Trojan_AndroidOS_SAgnt_AN_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.AN!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6d 73 52 65 73 75 6c 74 4c 69 73 74 65 6e 65 72 } //01 00  SmsResultListener
		$a_01_1 = {73 6d 73 5f 64 61 74 61 2e 74 78 74 } //01 00  sms_data.txt
		$a_01_2 = {72 75 2f 70 6c 61 79 66 6f 6e 2f 61 6e 64 72 6f 69 64 32 73 6d 73 2f 73 65 72 76 69 63 65 } //01 00  ru/playfon/android2sms/service
		$a_01_3 = {70 72 6f 63 65 73 73 53 6d 73 42 72 6f 61 64 63 61 73 74 } //01 00  processSmsBroadcast
		$a_01_4 = {6c 6f 61 64 54 65 78 74 46 72 6f 6d 41 73 73 65 74 73 } //01 00  loadTextFromAssets
		$a_01_5 = {73 6d 73 5f 73 75 63 63 65 73 73 } //00 00  sms_success
	condition:
		any of ($a_*)
 
}