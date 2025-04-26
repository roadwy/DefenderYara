
rule Trojan_AndroidOS_BrowBot_A_MTB{
	meta:
		description = "Trojan:AndroidOS/BrowBot.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 62 72 6f 77 73 65 72 2f 64 6f 77 6e 6c 6f 61 64 32 31 } //1 Lcom/browser/download21
		$a_01_1 = {53 6d 73 52 65 63 65 69 76 65 72 41 63 74 69 76 69 74 79 } //1 SmsReceiverActivity
		$a_01_2 = {61 38 70 2e 6e 65 74 2f 74 71 66 58 44 6e } //1 a8p.net/tqfXDn
		$a_01_3 = {74 74 70 73 3a 2f 2f 77 77 77 2e 61 70 69 6e 65 74 63 6f 6d 2e 63 6f 6d 2f 64 61 74 61 } //1 ttps://www.apinetcom.com/data
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}