
rule Trojan_AndroidOS_Rewardsteal_X{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.X,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 4d 53 5f 41 50 49 2f 73 65 74 5f 73 6d 73 5f 64 61 74 61 2e 70 68 70 } //2 SMS_API/set_sms_data.php
		$a_01_1 = {73 65 74 5f 75 73 65 72 5f 63 6f 6c 6c 65 63 74 6f 72 5f 64 61 74 61 2e 70 68 70 } //2 set_user_collector_data.php
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}