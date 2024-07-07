
rule Trojan_AndroidOS_AVPass_A_MTB{
	meta:
		description = "Trojan:AndroidOS/AVPass.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 74 70 3a 2f 2f 69 6e 74 65 72 66 61 63 65 2e 35 37 2e 6e 65 74 } //2 ttp://interface.57.net
		$a_01_1 = {7a 78 6c 79 5f 69 67 6e 6f 72 65 5f 61 70 70 67 72 61 64 65 5f 6c 69 73 74 } //2 zxly_ignore_appgrade_list
		$a_01_2 = {63 6d 64 3d 67 65 74 5f 69 6e 66 6f 5f } //1 cmd=get_info_
		$a_01_3 = {46 69 72 73 74 54 69 6d 65 4f 70 65 6e 41 70 70 54 65 78 74 } //1 FirstTimeOpenAppText
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}