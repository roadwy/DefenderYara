
rule Trojan_iPhoneOS_AceDeceiver_C_MTB{
	meta:
		description = "Trojan:iPhoneOS/AceDeceiver.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {68 69 64 64 65 6e 5f 65 78 74 72 61 5f 69 6e 66 6f } //1 hidden_extra_info
		$a_00_1 = {67 65 74 5f 75 73 65 72 5f 69 6e 66 6f } //1 get_user_info
		$a_00_2 = {3a 2f 2f 75 72 6c 2e 69 34 2e 63 6e } //1 ://url.i4.cn
		$a_00_3 = {6d 65 6d 62 65 72 5f 73 61 76 65 4c 6f 67 69 6e 49 6e 66 6f 2e 61 63 74 69 6f 6e } //1 member_saveLoginInfo.action
		$a_00_4 = {63 6f 6d 2e 74 65 69 72 6f 6e 2e 70 70 73 79 6e 63 } //1 com.teiron.ppsync
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}