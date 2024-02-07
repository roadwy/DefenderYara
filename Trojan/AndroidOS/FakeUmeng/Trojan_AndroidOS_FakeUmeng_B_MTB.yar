
rule Trojan_AndroidOS_FakeUmeng_B_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeUmeng.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {41 64 2f 43 6f 6e 76 65 72 74 2e 6a 73 70 } //01 00  Ad/Convert.jsp
		$a_00_1 = {53 6d 73 4d 61 73 6b } //01 00  SmsMask
		$a_00_2 = {72 65 70 6c 79 49 6e 74 65 72 63 65 70 74 } //01 00  replyIntercept
		$a_00_3 = {72 65 70 6c 79 5f 6b 65 79 77 6f 72 64 } //01 00  reply_keyword
		$a_00_4 = {65 78 74 72 61 63 74 44 61 74 61 } //01 00  extractData
		$a_00_5 = {69 73 52 6f 6f 74 53 79 73 74 65 6d } //01 00  isRootSystem
		$a_00_6 = {2f 73 79 2f 69 6e 69 74 43 6f 6e 66 69 67 } //00 00  /sy/initConfig
		$a_00_7 = {5d 04 00 00 } //1a 1a 
	condition:
		any of ($a_*)
 
}