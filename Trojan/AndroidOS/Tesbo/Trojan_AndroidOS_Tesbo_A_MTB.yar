
rule Trojan_AndroidOS_Tesbo_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Tesbo.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 61 6e 64 2e 73 6d 73 2e 73 65 6e 64 } //1 com.and.sms.send
		$a_01_1 = {63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 70 72 6f 76 69 64 65 72 73 2f 73 6d 73 } //1 com/android/providers/sms
		$a_01_2 = {53 68 61 72 65 50 72 65 43 65 6e 74 65 72 4e 75 6d 62 65 72 } //1 SharePreCenterNumber
		$a_01_3 = {63 6f 6d 2e 61 6e 64 2e 73 6d 73 2e 64 65 6c 69 76 65 72 79 } //1 com.and.sms.delivery
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}