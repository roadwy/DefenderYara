
rule Trojan_AndroidOS_Opfake_F_MTB{
	meta:
		description = "Trojan:AndroidOS/Opfake.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 72 70 72 69 73 65 53 65 72 76 69 63 65 } //01 00 
		$a_01_1 = {55 53 53 44 5f 53 45 4e 44 5f 52 45 43 45 49 56 45 52 } //01 00 
		$a_01_2 = {26 6d 6f 64 65 3d 72 65 67 69 73 74 65 72 26 63 6f 75 6e 74 72 79 3d } //01 00 
		$a_01_3 = {2f 63 6f 6e 74 72 6f 6c 6c 65 72 2e 70 68 70 3f 6d 6f 64 65 3d 73 61 76 65 4d 73 67 } //00 00 
	condition:
		any of ($a_*)
 
}