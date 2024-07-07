
rule Trojan_AndroidOS_uupay_A{
	meta:
		description = "Trojan:AndroidOS/uupay.A,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_00_0 = {64 6f 77 6e 6c 6f 61 64 53 75 63 63 65 73 73 41 64 } //2 downloadSuccessAd
		$a_00_1 = {6b 65 79 5f 69 67 6e 6f 72 65 5f 75 6e 69 6e 73 74 61 6c 6c 5f 72 75 62 62 69 73 68 5f 74 69 70 73 } //2 key_ignore_uninstall_rubbish_tips
		$a_00_2 = {6b 65 79 5f 70 72 6f 5f 6b 69 6c 6c 65 72 5f 77 68 69 74 65 5f 6c 69 73 74 } //2 key_pro_killer_white_list
		$a_00_3 = {50 55 53 48 5f 43 48 45 43 4b 5f 50 45 52 49 4f 49 44 } //2 PUSH_CHECK_PERIOID
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=8
 
}