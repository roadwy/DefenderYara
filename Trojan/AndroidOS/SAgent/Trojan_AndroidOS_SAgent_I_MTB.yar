
rule Trojan_AndroidOS_SAgent_I_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgent.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4d 53 48 61 6e 64 6c 65 72 31 2e 61 73 68 78 3f 74 3d 72 65 71 75 65 73 74 26 70 3d } //01 00 
		$a_01_1 = {47 65 74 41 6c 6c 43 6f 6e 74 61 63 74 4e 75 6d 62 65 72 73 } //01 00 
		$a_01_2 = {53 4d 53 53 65 72 76 69 63 65 42 6f 6f 74 52 65 63 65 69 76 65 72 } //01 00 
		$a_01_3 = {4d 53 47 5f 53 4e 45 44 5f 54 4f 5f 43 4f 4e 54 41 43 54 53 } //01 00 
		$a_01_4 = {53 4d 53 53 65 6e 64 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}