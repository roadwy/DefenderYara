
rule Trojan_AndroidOS_FakeApp_T{
	meta:
		description = "Trojan:AndroidOS/FakeApp.T,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {69 6d 67 74 78 74 78 74 78 74 78 74 78 74 78 74 67 69 } //1 imgtxtxtxtxtxtxtgi
		$a_01_1 = {67 6d 61 69 6c 66 6f 72 67 74 70 61 73 73 } //1 gmailforgtpass
		$a_01_2 = {64 65 75 74 73 63 68 6c 61 6e 64 63 36 34 } //1 deutschlandc64
		$a_01_3 = {66 6f 72 65 67 72 6f 75 6e 64 69 66 79 } //1 foregroundify
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}