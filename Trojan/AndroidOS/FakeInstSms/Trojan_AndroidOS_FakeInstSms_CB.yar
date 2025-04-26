
rule Trojan_AndroidOS_FakeInstSms_CB{
	meta:
		description = "Trojan:AndroidOS/FakeInstSms.CB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 73 6f 66 74 2f 61 6e 64 72 6f 69 64 2f 61 70 70 69 6e 73 74 61 6c 6c 65 72 2f 52 75 6c 65 73 41 63 74 69 76 69 74 79 } //1 Lcom/soft/android/appinstaller/RulesActivity
		$a_00_1 = {70 61 72 73 65 43 6f 6e 66 69 67 4c 69 6e 65 4d 43 43 4d 4e 43 } //1 parseConfigLineMCCMNC
		$a_00_2 = {67 65 74 53 6d 73 53 65 6e 74 43 6f 75 6e 74 } //1 getSmsSentCount
		$a_00_3 = {67 65 74 52 75 6c 65 73 54 65 78 74 73 } //1 getRulesTexts
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}