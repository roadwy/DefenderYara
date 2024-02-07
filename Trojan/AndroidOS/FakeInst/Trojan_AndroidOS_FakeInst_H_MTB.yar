
rule Trojan_AndroidOS_FakeInst_H_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeInst.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 72 67 2f 75 6e 66 69 6e 2f 64 65 76 } //01 00  org/unfin/dev
		$a_01_1 = {63 6f 6e 66 69 67 2e 74 78 74 } //01 00  config.txt
		$a_01_2 = {73 6d 73 53 65 6e 64 54 69 6d 65 } //01 00  smsSendTime
		$a_01_3 = {67 65 74 54 65 67 43 6f 6e 74 65 6e 74 } //01 00  getTegContent
		$a_01_4 = {52 25 68 6a 6b } //00 00  R%hjk
	condition:
		any of ($a_*)
 
}