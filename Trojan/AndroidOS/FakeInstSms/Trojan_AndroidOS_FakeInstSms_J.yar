
rule Trojan_AndroidOS_FakeInstSms_J{
	meta:
		description = "Trojan:AndroidOS/FakeInstSms.J,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 4f 66 66 65 72 74 41 63 74 69 76 69 74 79 3b } //01 00 
		$a_00_1 = {61 70 70 73 5f 64 69 72 5f 77 61 73 6e 74 5f 63 72 65 61 74 65 64 } //01 00 
		$a_00_2 = {69 6e 69 74 44 61 74 61 46 72 6f 6d 43 6f 6e 66 69 67 73 } //01 00 
		$a_00_3 = {69 6e 73 74 61 6c 6c 65 64 43 6f 6e 74 65 6e 74 54 65 78 74 56 69 65 77 } //01 00 
		$a_00_4 = {64 65 63 72 65 61 73 65 4e 6f 74 69 66 69 63 61 74 69 6f 6e 4e 75 6d 62 65 72 } //00 00 
		$a_00_5 = {5d 04 00 } //00 44 
	condition:
		any of ($a_*)
 
}