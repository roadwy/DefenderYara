
rule Trojan_AndroidOS_FakeInst_T_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeInst.T!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 66 69 72 74 69 6e 52 65 63 65 69 76 65 72 } //01 00  ConfirtinReceiver
		$a_01_1 = {46 4c 41 47 5f 43 4f 4e 46 49 52 4d 5f 4b 57 31 } //01 00  FLAG_CONFIRM_KW1
		$a_01_2 = {76 6e 69 74 6f 75 72 69 73 74 2e 63 6f 6d } //01 00  vnitourist.com
		$a_01_3 = {61 63 74 69 6f 6e 41 4f 43 } //00 00  actionAOC
	condition:
		any of ($a_*)
 
}