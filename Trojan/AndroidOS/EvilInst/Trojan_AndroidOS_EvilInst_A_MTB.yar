
rule Trojan_AndroidOS_EvilInst_A_MTB{
	meta:
		description = "Trojan:AndroidOS/EvilInst.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {76 6e 69 74 6f 75 72 69 73 74 2e 63 6f 6d } //1 vnitourist.com
		$a_01_1 = {76 6e 69 66 6f 6f 64 2e 63 6f 6d } //1 vnifood.com
		$a_01_2 = {6f 6e 65 73 69 67 6e 61 6c 2e 6d 6f 64 6f 62 6f 6d 63 6f 2e 63 6f 6d } //1 onesignal.modobomco.com
		$a_01_3 = {41 66 75 53 65 72 76 69 63 65 } //1 AfuService
		$a_01_4 = {61 63 74 69 6f 6e 41 4f 43 } //1 actionAOC
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}