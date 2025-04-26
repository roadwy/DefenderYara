
rule Trojan_AndroidOS_SendPay_A_MTB{
	meta:
		description = "Trojan:AndroidOS/SendPay.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 74 61 6c 6b 77 65 62 2f 69 6d 6f 6e 65 79 2f 4c 6f 61 64 4d 61 69 6e } //1 com/talkweb/imoney/LoadMain
		$a_01_1 = {67 75 61 67 75 61 64 61 74 65 } //1 guaguadate
		$a_01_2 = {69 6d 6f 6e 65 79 2e 64 62 } //1 imoney.db
		$a_01_3 = {63 6f 6d 2f 74 61 6c 6b 77 65 62 2f 69 6d 6f 6e 65 79 2f 61 6c 6d 61 6e 61 63 } //1 com/talkweb/imoney/almanac
		$a_01_4 = {62 61 6c 6c 42 75 79 4c 6f 67 } //1 ballBuyLog
		$a_01_5 = {42 61 6c 6c 42 65 61 6e 43 68 6f 69 63 65 } //1 BallBeanChoice
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}