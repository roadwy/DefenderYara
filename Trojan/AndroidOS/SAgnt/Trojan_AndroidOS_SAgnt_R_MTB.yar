
rule Trojan_AndroidOS_SAgnt_R_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.R!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 70 65 73 6f 63 72 65 64 69 74 2f 70 68 } //1 com/pesocredit/ph
		$a_01_1 = {53 65 72 76 69 63 65 44 65 74 65 63 74 6f 72 } //1 ServiceDetector
		$a_01_2 = {53 6d 73 4f 62 73 65 72 76 65 72 } //1 SmsObserver
		$a_01_3 = {48 64 62 74 69 53 65 72 76 69 63 65 } //1 HdbtiService
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}