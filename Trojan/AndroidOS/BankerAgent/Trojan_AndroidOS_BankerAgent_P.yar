
rule Trojan_AndroidOS_BankerAgent_P{
	meta:
		description = "Trojan:AndroidOS/BankerAgent.P,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {61 64 70 74 65 72 5f 73 6d 73 72 65 61 64 } //02 00  adpter_smsread
		$a_01_1 = {44 69 76 69 63 65 5f 42 6c 6f 63 6b } //02 00  Divice_Block
		$a_01_2 = {43 61 72 64 5f 52 65 55 70 6c 6f 61 64 } //00 00  Card_ReUpload
	condition:
		any of ($a_*)
 
}