
rule Trojan_AndroidOS_Feejar_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Feejar.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 6f 64 65 5f 66 6f 72 5f 73 6d 73 5f 69 6e 74 65 72 63 65 70 74 } //4 mode_for_sms_intercept
		$a_03_1 = {63 6f 6d 2f 63 90 02 15 2f 75 74 69 6c 2f 4e 65 74 77 6f 72 6b 53 74 61 74 65 52 65 63 65 69 76 65 72 90 00 } //2
		$a_01_2 = {6d 5f 73 6d 73 73 65 72 76 69 63 65 } //1 m_smsservice
		$a_01_3 = {72 69 74 6f 73 6d 73 66 65 65 70 61 67 65 } //1 ritosmsfeepage
	condition:
		((#a_01_0  & 1)*4+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}