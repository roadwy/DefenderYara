
rule Trojan_AndroidOS_Banker_T_MTB{
	meta:
		description = "Trojan:AndroidOS/Banker.T!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 61 72 64 20 69 6e 66 6f 72 6d 61 74 69 6f 6e } //01 00 
		$a_00_1 = {62 69 6c 6c 69 6e 67 20 63 72 65 64 65 6e 74 69 61 6c } //01 00 
		$a_00_2 = {63 6f 6d 2e 73 6c 65 6d 70 6f 2e 62 61 73 65 61 70 70 2e 4d 61 69 6e 53 65 72 76 69 63 65 53 74 61 72 74 } //01 00 
		$a_00_3 = {43 4f 4d 4d 42 41 4e 4b 5f 49 53 5f 53 45 4e 54 } //01 00 
		$a_00_4 = {69 6e 74 65 72 63 65 70 74 5f 73 6d 73 5f 73 74 61 72 74 } //00 00 
	condition:
		any of ($a_*)
 
}