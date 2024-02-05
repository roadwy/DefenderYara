
rule Trojan_AndroidOS_SpyAgent_V{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.V,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {26 6f 6e 63 65 73 6d 73 3d } //02 00 
		$a_01_1 = {26 61 63 74 69 6f 6e 3d 73 6d 73 26 6e 65 74 77 6f 72 6b 3d } //02 00 
		$a_01_2 = {5f 73 65 74 5f 61 63 74 5f 65 6e 61 62 6c 65 64 } //02 00 
		$a_01_3 = {26 61 63 74 69 6f 6e 3d 6f 66 66 73 74 61 74 75 73 64 69 73 } //00 00 
	condition:
		any of ($a_*)
 
}