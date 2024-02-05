
rule Trojan_AndroidOS_SAgnt_AM_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.AM!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 53 47 5f 53 4e 45 44 5f 54 4f 5f 43 4f 4e 54 41 43 54 53 } //01 00 
		$a_01_1 = {67 65 74 53 49 4d 43 6f 6e 74 61 63 74 4e 75 6d 62 65 72 73 } //01 00 
		$a_03_2 = {53 4d 53 48 61 6e 64 6c 65 72 90 02 10 61 73 68 78 3f 74 3d 73 26 70 3d 90 00 } //01 00 
		$a_01_3 = {57 65 62 53 65 72 76 69 63 65 43 61 6c 6c 69 6e 67 } //01 00 
		$a_01_4 = {53 65 6e 64 54 6f 43 6f 6e 74 61 63 74 73 } //01 00 
		$a_01_5 = {63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 67 6f 6f 67 6c 65 2f 73 65 72 76 69 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}