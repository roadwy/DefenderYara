
rule Trojan_AndroidOS_SpyBanker_AY{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.AY,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {67 61 74 65 77 61 79 2f 6f 70 74 69 6f 6e 5f 61 63 74 69 76 69 74 79 } //2 gateway/option_activity
		$a_01_1 = {69 6e 63 6f 6d 69 6e 67 73 6d 73 67 61 74 65 77 61 79 2f 53 6d 73 4d 61 69 6e 41 63 74 69 76 69 74 79 } //2 incomingsmsgateway/SmsMainActivity
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}