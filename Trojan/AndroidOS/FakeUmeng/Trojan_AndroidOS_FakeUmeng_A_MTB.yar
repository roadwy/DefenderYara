
rule Trojan_AndroidOS_FakeUmeng_A_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeUmeng.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 75 6d 65 6e 67 2f 61 64 75 74 69 6c 73 2f 41 64 73 43 6f 6e 6e 65 63 74 } //01 00 
		$a_00_1 = {44 69 61 6e 6c 65 48 61 6e 64 6c 65 } //01 00 
		$a_00_2 = {2f 4d 79 41 64 2f 43 6f 6e 76 65 72 74 2e 6a 73 70 } //01 00 
		$a_00_3 = {44 61 74 6f 75 6e 69 61 6f 48 61 6e 64 6c 65 72 } //01 00 
		$a_00_4 = {73 6d 73 43 6f 6e 74 65 6e 74 } //01 00 
		$a_00_5 = {65 78 74 72 61 63 74 44 61 74 61 } //00 00 
		$a_00_6 = {5d 04 00 00 } //19 1a 
	condition:
		any of ($a_*)
 
}