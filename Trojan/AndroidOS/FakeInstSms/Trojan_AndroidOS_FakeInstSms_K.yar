
rule Trojan_AndroidOS_FakeInstSms_K{
	meta:
		description = "Trojan:AndroidOS/FakeInstSms.K,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 65 74 72 6f 6f 6c 73 64 69 73 70 6c 61 79 } //01 00 
		$a_00_1 = {73 68 6f 77 6d 65 73 73 69 6e 74 65 72 6e 65 74 } //01 00 
		$a_00_2 = {2f 50 72 6f 69 6e 41 63 74 69 76 69 74 79 3b } //01 00 
		$a_00_3 = {63 6f 6e 66 69 67 70 61 63 68 } //01 00 
		$a_00_4 = {72 6f 6f 6c 73 2e 74 78 74 } //01 00 
		$a_00_5 = {45 53 4c 49 41 42 4f 4e 45 4e 54 54 55 50 49 54 } //00 00 
		$a_00_6 = {5d 04 00 } //00 45 
	condition:
		any of ($a_*)
 
}