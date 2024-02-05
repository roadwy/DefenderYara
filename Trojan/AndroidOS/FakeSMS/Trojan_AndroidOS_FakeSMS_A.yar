
rule Trojan_AndroidOS_FakeSMS_A{
	meta:
		description = "Trojan:AndroidOS/FakeSMS.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {73 5f 6d 73 6f 66 74 73 } //02 00 
		$a_01_1 = {6e 73 65 76 33 37 35 } //02 00 
		$a_01_2 = {61 66 6f 6e 50 72 69 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}