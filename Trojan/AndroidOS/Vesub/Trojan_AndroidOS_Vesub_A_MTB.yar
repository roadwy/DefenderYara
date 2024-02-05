
rule Trojan_AndroidOS_Vesub_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Vesub.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 79 73 2f 6d 6f 64 6f 62 6f 6d 2f 73 75 62 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //01 00 
		$a_00_1 = {6d 6f 64 6f 62 6f 6d 2e 73 65 72 76 69 63 65 73 2f 61 70 69 2f 73 75 62 73 } //01 00 
		$a_00_2 = {6e 6f 74 69 66 69 2f 4e 6f 74 69 66 69 63 61 74 69 6f 6e 50 75 73 68 4d 61 73 73 61 67 65 } //01 00 
		$a_00_3 = {73 75 62 2f 73 65 72 76 69 63 65 73 2f 53 6d 73 52 65 63 65 69 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}