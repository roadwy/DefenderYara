
rule Trojan_AndroidOS_BankerAgent_KJ{
	meta:
		description = "Trojan:AndroidOS/BankerAgent.KJ,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {2f 62 2e 6b 75 6e 6c 75 6e 36 36 36 2e 78 79 7a 2f 23 2f } //02 00  /b.kunlun666.xyz/#/
		$a_01_1 = {69 73 5f 6c 6f 63 6b 65 64 5f 64 65 76 69 63 65 } //02 00  is_locked_device
		$a_01_2 = {69 73 5f 73 75 63 63 65 73 73 5f 67 65 74 5f 70 65 72 6d 69 73 73 69 6f 6e 73 } //00 00  is_success_get_permissions
	condition:
		any of ($a_*)
 
}