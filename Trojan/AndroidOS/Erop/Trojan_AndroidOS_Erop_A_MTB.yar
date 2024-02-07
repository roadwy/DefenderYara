
rule Trojan_AndroidOS_Erop_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Erop.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 65 72 6f 70 6c 61 79 65 72 } //01 00  com/example/eroplayer
		$a_01_1 = {69 73 5f 73 6d 73 } //01 00  is_sms
		$a_01_2 = {6f 6e 52 75 6c 65 73 42 75 74 74 6f 6e 43 6c 69 63 6b } //01 00  onRulesButtonClick
		$a_01_3 = {62 6f 72 6e 61 70 6b 2e 63 6f 6d } //01 00  bornapk.com
		$a_01_4 = {6f 6e 53 6d 73 42 75 74 74 6f 6e 43 6c 69 63 6b } //00 00  onSmsButtonClick
	condition:
		any of ($a_*)
 
}