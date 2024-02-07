
rule Trojan_AndroidOS_Tinybee_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Tinybee.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {54 69 6e 79 62 65 65 4c 6f 67 67 65 72 } //01 00  TinybeeLogger
		$a_00_1 = {74 69 6e 79 62 65 65 2e 73 61 76 65 6e 75 6d 62 65 72 2e 63 6f 6d } //01 00  tinybee.savenumber.com
		$a_00_2 = {74 65 73 74 2e 67 61 6c 6c 2e 6d 65 2f 74 69 6e 79 62 65 65 2f } //01 00  test.gall.me/tinybee/
		$a_00_3 = {49 74 20 69 73 20 61 20 53 4d 53 20 42 69 6c 6c 69 6e 67 } //01 00  It is a SMS Billing
		$a_00_4 = {64 61 2e 6d 6d 61 72 6b 65 74 2e 63 6f 6d } //00 00  da.mmarket.com
	condition:
		any of ($a_*)
 
}