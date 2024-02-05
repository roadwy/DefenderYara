
rule Trojan_AndroidOS_SAgnt_Y_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.Y!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 61 74 61 73 74 61 74 69 73 61 70 69 2e 7a 68 75 69 66 65 6e 67 7a 68 65 2e 74 6f 70 } //01 00 
		$a_01_1 = {2f 6c 6f 67 72 65 70 6f 72 74 } //01 00 
		$a_01_2 = {2f 76 31 2f 6d 72 3f 69 64 3d } //01 00 
		$a_01_3 = {61 6e 64 72 6f 69 64 2e 61 70 70 2e 41 70 70 47 6c 6f 62 61 6c 73 } //00 00 
	condition:
		any of ($a_*)
 
}