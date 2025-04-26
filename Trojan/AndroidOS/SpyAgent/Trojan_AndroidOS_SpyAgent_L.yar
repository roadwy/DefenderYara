
rule Trojan_AndroidOS_SpyAgent_L{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.L,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4f 6e 65 6e 74 65 72 5f 6f 6e 45 6e 74 65 72 } //1 Onenter_onEnter
		$a_01_1 = {4f 6e 45 78 69 74 5f 63 74 78 41 72 72 79 } //1 OnExit_ctxArry
		$a_01_2 = {74 6a 66 2e 72 78 69 77 2e 67 73 77 72 } //1 tjf.rxiw.gswr
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_AndroidOS_SpyAgent_L_2{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.L,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 67 31 2e 6d 61 6c 6c 2d 62 61 73 65 2d 61 70 70 } //2 sg1.mall-base-app
		$a_01_1 = {4d 61 69 6e 53 6d 73 41 63 74 69 76 69 74 79 53 74 61 72 74 } //2 MainSmsActivityStart
		$a_01_2 = {4e 61 74 69 76 65 5f 52 45 53 55 4c 54 5f 4b 45 59 } //2 Native_RESULT_KEY
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}