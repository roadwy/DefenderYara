
rule Trojan_AndroidOS_Smaps_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Smaps.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 73 79 73 74 65 6d 2f 75 70 64 61 74 65 5f 73 65 74 74 69 6e 67 } //1 com/system/update_setting
		$a_01_1 = {4f 61 73 65 74 74 69 6e 67 } //1 Oasetting
		$a_01_2 = {63 6f 6d 2f 6c 61 75 6e 63 68 65 72 2f 73 65 74 74 69 6e 67 } //1 com/launcher/setting
		$a_01_3 = {76 6b 2e 63 6f 6d 2f } //1 vk.com/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}