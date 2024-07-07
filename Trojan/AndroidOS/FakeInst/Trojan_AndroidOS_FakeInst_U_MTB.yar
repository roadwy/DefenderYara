
rule Trojan_AndroidOS_FakeInst_U_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeInst.U!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {70 64 70 5f 74 65 78 74 5f 6d 66 5f 65 6e 64 } //1 pdp_text_mf_end
		$a_01_1 = {69 73 4d 54 53 53 75 62 73 63 72 69 70 74 69 6f 6e } //1 isMTSSubscription
		$a_01_2 = {69 73 4d 46 53 75 62 73 63 72 69 70 74 69 6f 6e } //1 isMFSubscription
		$a_01_3 = {73 65 6e 64 4d 73 67 } //1 sendMsg
		$a_01_4 = {47 4f 54 5f 4d 45 53 53 41 47 45 5f 52 45 53 50 5f 4b 45 59 } //1 GOT_MESSAGE_RESP_KEY
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}