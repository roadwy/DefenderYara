
rule Trojan_AndroidOS_Razel_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Razel.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 74 65 61 6c 43 6f 6e 74 61 63 74 73 } //1 stealContacts
		$a_01_1 = {73 74 65 61 6c 53 4d 53 } //1 stealSMS
		$a_01_2 = {5f 73 74 65 61 6c 4c 6f 67 } //1 _stealLog
		$a_01_3 = {5f 66 69 6e 64 50 69 63 73 } //1 _findPics
		$a_01_4 = {73 74 65 61 6c 57 68 61 74 73 61 70 70 } //1 stealWhatsapp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}