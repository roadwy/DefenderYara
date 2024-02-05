
rule Trojan_AndroidOS_MobiOk_A_MTB{
	meta:
		description = "Trojan:AndroidOS/MobiOk.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6c 6f 6c 65 65 63 74 20 73 6d 73 2d 2d 2d } //01 00 
		$a_00_1 = {32 63 61 70 74 63 68 61 2e 63 6f 6d 2f 69 6e 2e 70 68 70 } //01 00 
		$a_00_2 = {73 65 6e 64 4d 75 6c 74 69 70 61 72 74 53 6d 73 } //01 00 
		$a_00_3 = {55 70 6c 6f 61 64 2f 50 72 6f 63 65 73 73 69 6e 67 2e 70 68 70 } //01 00 
		$a_00_4 = {6f 6e 4a 73 47 65 74 50 68 6f 6e 65 4e 75 6d 62 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}