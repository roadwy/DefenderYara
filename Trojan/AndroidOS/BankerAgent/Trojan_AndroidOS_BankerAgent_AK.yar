
rule Trojan_AndroidOS_BankerAgent_AK{
	meta:
		description = "Trojan:AndroidOS/BankerAgent.AK,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 61 70 69 2f 62 69 6e 67 6f 70 6c 75 73 5f 67 65 74 5f 70 68 6f 6e 65 5f 6e 75 6d 62 65 72 5f 73 74 61 74 75 73 } //2 /api/bingoplus_get_phone_number_status
		$a_01_1 = {62 69 6e 67 6f 50 6c 75 73 50 61 73 73 77 6f 72 64 } //2 bingoPlusPassword
		$a_01_2 = {7a 61 65 62 61 6c 2f 63 6f 72 65 2f 53 6d 73 4d 65 73 73 61 67 65 52 65 63 65 69 76 65 72 } //4 zaebal/core/SmsMessageReceiver
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*4) >=4
 
}