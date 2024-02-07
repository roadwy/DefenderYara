
rule TrojanSpy_AndroidOS_WyrmSpy_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/WyrmSpy.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0b 00 0b 00 04 00 00 05 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 66 6c 61 73 68 31 38 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //05 00  com/flash18/MainActivity
		$a_00_1 = {46 61 6b 65 41 63 74 69 76 69 74 79 } //01 00  FakeActivity
		$a_00_2 = {43 68 61 6e 67 65 51 75 69 63 6b 52 65 64 69 72 65 63 74 } //01 00  ChangeQuickRedirect
		$a_00_3 = {73 65 72 76 69 63 65 5f 69 6e 76 6f 6b 65 72 } //00 00  service_invoker
	condition:
		any of ($a_*)
 
}