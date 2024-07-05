
rule Trojan_AndroidOS_SmsThief_K_MTB{
	meta:
		description = "Trojan:AndroidOS/SmsThief.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 07 00 00 05 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 6f 6d 65 72 2f 73 6d 73 61 70 70 34 } //05 00  Lcom/omer/smsapp4
		$a_01_1 = {63 6f 6d 2e 72 65 64 65 65 6d 2e 52 65 64 65 65 6d 5f 70 6f 69 6e 74 73 } //01 00  com.redeem.Redeem_points
		$a_01_2 = {69 6e 73 65 72 74 4d 73 67 64 61 74 61 } //01 00  insertMsgdata
		$a_01_3 = {76 65 72 75 66 79 5f 6f 74 70 5f 6d 6f 64 65 6c } //01 00  verufy_otp_model
		$a_01_4 = {73 75 62 6d 69 74 5f 73 6d 73 2e 70 68 70 } //01 00  submit_sms.php
		$a_01_5 = {53 6d 73 42 72 6f 61 64 63 61 73 72 52 65 63 65 69 76 65 72 } //01 00  SmsBroadcasrReceiver
		$a_01_6 = {73 65 6e 64 64 61 74 61 74 6f 64 62 } //00 00  senddatatodb
	condition:
		any of ($a_*)
 
}