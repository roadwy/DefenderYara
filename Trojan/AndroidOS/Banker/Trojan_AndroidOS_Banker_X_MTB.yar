
rule Trojan_AndroidOS_Banker_X_MTB{
	meta:
		description = "Trojan:AndroidOS/Banker.X!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 44 5f 53 61 76 65 5f 6b 61 72 6f } //1 ID_Save_karo
		$a_01_1 = {64 61 74 61 5f 61 6c 65 72 74 } //1 data_alert
		$a_01_2 = {53 65 6e 74 5f 49 6e 73 74 61 6c 6c } //1 Sent_Install
		$a_01_3 = {53 65 6e 64 43 61 72 64 4e 6f 64 65 50 6f 73 74 } //1 SendCardNodePost
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}