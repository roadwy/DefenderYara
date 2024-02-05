
rule Trojan_AndroidOS_Opfake_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Opfake.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 75 74 43 61 6c 6c 52 65 63 65 69 76 65 72 } //01 00 
		$a_01_1 = {4f 75 74 4d 73 67 52 65 63 65 69 76 65 72 } //01 00 
		$a_01_2 = {71 70 63 6c 69 63 6b 2e 63 6f 6d } //01 00 
		$a_01_3 = {53 65 6e 64 41 63 74 69 76 69 74 79 } //01 00 
		$a_01_4 = {73 65 74 54 61 73 6b 2e 70 68 70 3f 69 64 3d } //00 00 
	condition:
		any of ($a_*)
 
}