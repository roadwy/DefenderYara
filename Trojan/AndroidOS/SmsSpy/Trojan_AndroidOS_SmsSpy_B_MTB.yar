
rule Trojan_AndroidOS_SmsSpy_B_MTB{
	meta:
		description = "Trojan:AndroidOS/SmsSpy.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 7a 62 6a 2f 75 70 6c 6f 61 64 69 6e 66 6f 2f 55 70 6c 6f 61 64 4f 75 74 53 6d 73 54 68 72 65 61 64 3b } //01 00 
		$a_00_1 = {2f 61 70 69 5f 76 69 73 69 74 2e 70 68 70 3f 6e 75 6d 62 65 72 3d } //01 00 
		$a_00_2 = {53 6d 73 55 70 6c 6f 61 64 53 65 72 76 69 63 65 } //01 00 
		$a_00_3 = {75 70 6c 6f 61 64 43 6f 6e 74 61 63 74 73 } //00 00 
	condition:
		any of ($a_*)
 
}