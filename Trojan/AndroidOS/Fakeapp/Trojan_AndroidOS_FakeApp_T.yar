
rule Trojan_AndroidOS_FakeApp_T{
	meta:
		description = "Trojan:AndroidOS/FakeApp.T,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 6d 67 74 78 74 78 74 78 74 78 74 78 74 78 74 67 69 } //01 00 
		$a_01_1 = {67 6d 61 69 6c 66 6f 72 67 74 70 61 73 73 } //01 00 
		$a_01_2 = {64 65 75 74 73 63 68 6c 61 6e 64 63 36 34 } //01 00 
		$a_01_3 = {66 6f 72 65 67 72 6f 75 6e 64 69 66 79 } //00 00 
	condition:
		any of ($a_*)
 
}