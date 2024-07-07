
rule Adware_AndroidOS_IconHider_A_MTB{
	meta:
		description = "Adware:AndroidOS/IconHider.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 61 70 69 2e 31 6f 63 65 61 6e 73 2e 63 6f 6d } //1 mapi.1oceans.com
		$a_01_1 = {67 65 74 43 6c 69 63 6b 53 70 } //1 getClickSp
		$a_01_2 = {63 6c 69 63 6b 44 65 6c 61 79 54 69 6d 65 } //1 clickDelayTime
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}