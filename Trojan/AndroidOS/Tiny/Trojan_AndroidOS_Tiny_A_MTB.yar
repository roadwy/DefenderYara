
rule Trojan_AndroidOS_Tiny_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Tiny.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 5f 67 65 74 73 6d 73 63 6f 64 65 } //1 s_getsmscode
		$a_01_1 = {72 65 5f 63 6f 6e 66 69 72 6d 5f 6d 61 74 63 68 5f 70 68 6f 6e 65 } //1 re_confirm_match_phone
		$a_01_2 = {6c 74 70 61 79 72 65 71 } //1 ltpayreq
		$a_01_3 = {79 7a 6d 5f 63 6f 6e 74 65 6e 74 5f 70 72 65 } //1 yzm_content_pre
		$a_01_4 = {49 53 50 41 59 55 4e 46 41 49 52 4c 4f 53 54 } //1 ISPAYUNFAIRLOST
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}