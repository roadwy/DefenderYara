
rule Trojan_AndroidOS_SAgnt_I_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 6c 75 65 2f 73 6b 79 2f 76 6e 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //01 00  blue/sky/vn/MainActivity
		$a_01_1 = {74 79 70 65 5f 67 65 74 5f 6c 69 6e 6b } //01 00  type_get_link
		$a_01_2 = {4b 45 4e 52 65 63 65 69 76 65 72 } //01 00  KENReceiver
		$a_01_3 = {4f 70 65 6e 4c 69 6e 6b 4e 6f 74 69 66 79 } //00 00  OpenLinkNotify
	condition:
		any of ($a_*)
 
}