
rule Trojan_AndroidOS_SpyAgent_NS{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.NS,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 6e 74 65 6e 74 5f 53 65 72 76 69 63 65 5f 63 68 65 63 6b 5f 74 65 73 74 } //2 Intent_Service_check_test
		$a_01_1 = {63 68 65 63 6b 5f 75 70 64 61 74 65 3f 76 65 72 3d 61 62 63 64 } //2 check_update?ver=abcd
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}