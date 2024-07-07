
rule Trojan_AndroidOS_SpyBanker_B_MTB{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 73 6d 65 74 69 71 2e 66 6c } //1 cosmetiq.fl
		$a_01_1 = {53 6d 73 4b 69 74 4b 61 74 53 65 72 76 69 63 65 } //1 SmsKitKatService
		$a_01_2 = {49 6e 63 6f 6d 65 53 4d 53 41 63 74 69 76 69 74 79 } //1 IncomeSMSActivity
		$a_01_3 = {62 6f 74 5f 69 64 } //1 bot_id
		$a_01_4 = {75 70 6c 6f 61 64 5f 73 6d 73 } //1 upload_sms
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}