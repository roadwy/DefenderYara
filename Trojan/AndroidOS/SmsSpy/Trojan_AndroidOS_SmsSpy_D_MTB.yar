
rule Trojan_AndroidOS_SmsSpy_D_MTB{
	meta:
		description = "Trojan:AndroidOS/SmsSpy.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 74 61 72 74 20 6d 6f 6f 6e 5f 73 65 6e 64 5f 73 6d 73 } //01 00 
		$a_00_1 = {6d 6f 6f 6e 5f 73 79 73 5f 69 6e 73 74 61 6c 6c 5f 61 70 70 20 73 74 61 72 74 20 69 6e 73 74 61 6c 6c 20 61 70 6b } //01 00 
		$a_00_2 = {6d 6f 6f 6e 5f 73 79 73 5f 67 65 74 5f 75 73 65 72 69 6e 66 6f } //01 00 
		$a_00_3 = {4d 4f 4e 49 54 4f 52 53 4d 53 } //01 00 
		$a_00_4 = {61 6b 6e 73 65 72 76 65 72 5f 70 74 6c 2e 64 61 74 } //00 00 
		$a_00_5 = {be 9f 00 } //00 05 
	condition:
		any of ($a_*)
 
}
rule Trojan_AndroidOS_SmsSpy_D_MTB_2{
	meta:
		description = "Trojan:AndroidOS/SmsSpy.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 6e 65 74 2f 6d 61 6e 61 67 65 72 2f 43 61 6c 6c 55 70 6c 6f 61 64 4d 61 6e 61 67 65 72 3b } //01 00 
		$a_00_1 = {2f 6d 6f 6e 69 74 6f 72 2f 53 6d 73 4d 6f 6e 69 74 6f 72 3b } //01 00 
		$a_00_2 = {53 6d 73 55 70 6c 6f 61 64 4d 61 6e 61 67 65 72 20 72 65 73 70 6f 6e 73 65 } //01 00 
		$a_00_3 = {2f 41 6e 64 72 6f 69 64 2f 53 6d 61 2f 4c 6f 67 } //01 00 
		$a_00_4 = {2f 6d 6f 62 69 6c 65 2f 6d 65 74 68 6f 64 34 } //01 00 
		$a_00_5 = {2f 6d 6f 62 69 6c 65 2f 75 70 6c 6f 61 64 53 6d 73 } //00 00 
		$a_00_6 = {5d 04 00 00 } //52 ff 
	condition:
		any of ($a_*)
 
}