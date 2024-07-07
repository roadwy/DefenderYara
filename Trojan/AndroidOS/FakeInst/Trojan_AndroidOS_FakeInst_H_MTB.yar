
rule Trojan_AndroidOS_FakeInst_H_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeInst.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6f 72 67 2f 75 6e 66 69 6e 2f 64 65 76 } //1 org/unfin/dev
		$a_01_1 = {63 6f 6e 66 69 67 2e 74 78 74 } //1 config.txt
		$a_01_2 = {73 6d 73 53 65 6e 64 54 69 6d 65 } //1 smsSendTime
		$a_01_3 = {67 65 74 54 65 67 43 6f 6e 74 65 6e 74 } //1 getTegContent
		$a_01_4 = {52 25 68 6a 6b } //1 R%hjk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}