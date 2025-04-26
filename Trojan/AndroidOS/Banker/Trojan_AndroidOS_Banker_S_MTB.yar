
rule Trojan_AndroidOS_Banker_S_MTB{
	meta:
		description = "Trojan:AndroidOS/Banker.S!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 4d 53 46 6f 72 77 61 72 64 53 65 72 76 69 63 65 } //1 SMSForwardService
		$a_01_1 = {63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 63 32 62 6f 74 6e 65 74 } //1 com/example/c2botnet
		$a_01_2 = {53 4d 53 46 6f 72 77 61 72 64 65 72 } //1 SMSForwarder
		$a_01_3 = {73 65 74 52 65 6d 6f 74 65 49 6e 70 75 74 48 69 73 74 6f 72 79 } //1 setRemoteInputHistory
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}