
rule Trojan_AndroidOS_SmsAgent_AZ{
	meta:
		description = "Trojan:AndroidOS/SmsAgent.AZ,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {70 6f 6c 61 6e 64 5f 78 78 78 31 37 2f 46 61 69 6c 65 64 41 63 74 69 76 69 74 79 } //2 poland_xxx17/FailedActivity
		$a_01_1 = {70 6f 6c 61 6e 64 5f 78 78 78 31 37 2f 52 75 6c 65 73 41 63 74 69 76 69 74 79 } //2 poland_xxx17/RulesActivity
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}