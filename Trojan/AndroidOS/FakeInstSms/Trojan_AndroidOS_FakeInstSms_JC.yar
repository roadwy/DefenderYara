
rule Trojan_AndroidOS_FakeInstSms_JC{
	meta:
		description = "Trojan:AndroidOS/FakeInstSms.JC,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {21 21 21 64 65 76 69 63 65 5f 69 64 3d } //01 00 
		$a_01_1 = {4c 63 6f 6d 2f 65 78 74 65 6e 64 2f 62 61 74 74 65 72 79 2f } //01 00 
		$a_01_2 = {50 52 45 46 5f 4c 41 53 54 5f 49 4e 53 54 41 4c 4c 45 44 5f 56 45 52 53 49 4f 4e } //00 00 
	condition:
		any of ($a_*)
 
}