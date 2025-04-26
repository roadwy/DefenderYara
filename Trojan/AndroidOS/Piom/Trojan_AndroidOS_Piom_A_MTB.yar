
rule Trojan_AndroidOS_Piom_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Piom.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 63 6f 72 6f 6e 61 73 61 66 65 74 79 6d 61 73 6b 2e 61 70 70 } //1 com.coronasafetymask.app
		$a_00_1 = {73 6d 73 73 65 6e 74 } //1 smssent
		$a_00_2 = {71 75 65 72 79 28 50 68 6f 6e 65 2e 43 4f 4e 54 45 4e 54 5f 55 52 49 } //1 query(Phone.CONTENT_URI
		$a_00_3 = {70 65 72 6d 69 73 73 69 6f 6e 2e 53 45 4e 44 5f 53 4d 53 } //1 permission.SEND_SMS
		$a_00_4 = {63 6f 72 6f 6e 61 73 61 66 65 74 79 6d 61 73 6b 2e 74 6b } //1 coronasafetymask.tk
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}