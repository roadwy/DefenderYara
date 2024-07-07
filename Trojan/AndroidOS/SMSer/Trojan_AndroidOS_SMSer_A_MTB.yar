
rule Trojan_AndroidOS_SMSer_A_MTB{
	meta:
		description = "Trojan:AndroidOS/SMSer.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 61 6c 6d 66 75 6e 70 6c 61 79 2e 63 6e } //1 palmfunplay.cn
		$a_00_1 = {2f 66 70 6c 61 79 5f 61 72 74 68 63 } //1 /fplay_arthc
		$a_00_2 = {69 73 53 4d 53 53 65 6e 64 53 75 63 63 65 65 64 } //1 isSMSSendSucceed
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}