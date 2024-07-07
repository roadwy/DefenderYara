
rule TrojanDropper_AndroidOS_Wroba_E_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Wroba.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 68 69 6e 68 61 6e 5f 73 65 6e 64 5f 70 77 64 } //1 shinhan_send_pwd
		$a_01_1 = {68 69 64 64 65 5f 69 64 } //1 hidde_id
		$a_01_2 = {73 68 69 6e 68 61 6e 5f 63 61 72 64 5f 6e 75 6d 62 65 72 } //1 shinhan_card_number
		$a_01_3 = {77 6f 6f 72 69 5f 6d 61 69 6e 5f 61 63 74 69 76 69 74 79 } //1 woori_main_activity
		$a_01_4 = {68 61 6e 61 5f 6d 61 69 6e 5f 61 63 74 69 76 69 74 79 20 } //1 hana_main_activity 
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}