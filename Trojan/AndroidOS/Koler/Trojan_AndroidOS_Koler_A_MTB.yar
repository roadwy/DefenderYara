
rule Trojan_AndroidOS_Koler_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Koler.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {26 62 72 6f 6b 3d 65 6d 70 74 79 26 75 3d 33 } //01 00 
		$a_01_1 = {63 6f 6d 2f 6c 6f 63 6b 2f 61 70 70 2f 53 74 61 72 74 53 68 6f 77 41 63 74 69 76 69 74 79 } //01 00 
		$a_01_2 = {2f 73 65 6e 64 2e 70 68 70 3f 76 3d } //01 00 
		$a_01_3 = {53 74 61 72 74 4f 76 56 69 65 77 } //00 00 
	condition:
		any of ($a_*)
 
}