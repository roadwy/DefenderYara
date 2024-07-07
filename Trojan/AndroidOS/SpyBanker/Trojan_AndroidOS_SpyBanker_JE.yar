
rule Trojan_AndroidOS_SpyBanker_JE{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.JE,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 66 69 74 46 65 65 64 62 61 63 6b 53 65 6e 64 65 72 } //2 ProfitFeedbackSender
		$a_01_1 = {53 65 6e 64 46 65 65 64 62 61 63 6b 53 63 72 69 70 74 } //2 SendFeedbackScript
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}