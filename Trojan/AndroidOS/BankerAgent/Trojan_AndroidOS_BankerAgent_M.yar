
rule Trojan_AndroidOS_BankerAgent_M{
	meta:
		description = "Trojan:AndroidOS/BankerAgent.M,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 53 6d 73 74 6f 65 72 76 65 72 } //2 sendSmstoerver
		$a_01_1 = {61 70 69 2f 61 70 70 2f 63 6c 69 65 6e 74 5f 64 65 74 61 69 6c 73 } //2 api/app/client_details
		$a_01_2 = {72 65 63 65 69 76 65 72 2f 53 6d 73 52 65 70 6f 73 69 74 6f 72 79 } //2 receiver/SmsRepository
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=4
 
}