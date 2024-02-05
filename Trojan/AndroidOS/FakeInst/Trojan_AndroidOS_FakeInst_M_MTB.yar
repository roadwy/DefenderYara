
rule Trojan_AndroidOS_FakeInst_M_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeInst.M!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {35 24 14 00 48 06 09 04 48 07 08 05 b7 76 8d 66 4f 06 03 04 d8 05 05 01 d8 06 01 ff 37 65 03 00 01 05 d8 04 04 01 28 ed } //01 00 
		$a_01_1 = {63 6f 6d 2f 73 6c 61 63 6b 65 6e 2f 77 6f 72 6b 2f 6d 69 73 63 68 69 65 } //00 00 
	condition:
		any of ($a_*)
 
}