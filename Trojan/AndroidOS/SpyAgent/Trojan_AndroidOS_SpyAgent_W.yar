
rule Trojan_AndroidOS_SpyAgent_W{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.W,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {6f 6e 75 73 63 72 65 61 74 65 73 } //02 00 
		$a_01_1 = {70 68 69 73 64 61 74 61 73 65 74 75 70 } //02 00 
		$a_01_2 = {2f 61 70 6b 66 72 6f 6d 68 65 6c 6c 74 6f 79 6f 75 66 6f 72 74 68 69 73 } //00 00 
	condition:
		any of ($a_*)
 
}