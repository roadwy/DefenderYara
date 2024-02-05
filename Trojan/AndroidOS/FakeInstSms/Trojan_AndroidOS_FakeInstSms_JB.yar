
rule Trojan_AndroidOS_FakeInstSms_JB{
	meta:
		description = "Trojan:AndroidOS/FakeInstSms.JB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 45 76 76 75 68 6a 51 73 6a 79 6c 79 6a 4f 3b } //01 00 
		$a_01_1 = {2f 44 65 6a 79 76 79 73 71 6a 65 68 3b } //01 00 
		$a_01_2 = {2f 51 73 6a 65 68 3b } //00 00 
	condition:
		any of ($a_*)
 
}