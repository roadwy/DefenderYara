
rule Trojan_AndroidOS_SmsThief_AP{
	meta:
		description = "Trojan:AndroidOS/SmsThief.AP,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {77 65 62 73 65 72 76 69 63 65 73 2f 72 65 67 69 73 74 65 72 5f 75 73 65 72 5f 6f 6e 6c 69 6e 65 5f 62 61 6e 6b 69 6e 67 2e 70 68 70 3f } //2 webservices/register_user_online_banking.php?
		$a_01_1 = {77 65 62 73 65 72 76 69 63 65 73 2f 61 64 64 5f 73 6d 73 2e 70 68 70 3f } //2 webservices/add_sms.php?
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}