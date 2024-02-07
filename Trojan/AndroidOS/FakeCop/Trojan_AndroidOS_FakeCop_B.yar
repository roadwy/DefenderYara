
rule Trojan_AndroidOS_FakeCop_B{
	meta:
		description = "Trojan:AndroidOS/FakeCop.B,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 50 5f 52 45 47 49 53 54 45 52 5f 49 4e 46 4f } //01 00  UP_REGISTER_INFO
		$a_01_1 = {2e 6a 6f 62 73 2e 57 68 61 74 53 65 72 76 69 63 65 } //01 00  .jobs.WhatService
		$a_01_2 = {55 50 5f 4d 45 53 53 41 47 45 5f 42 52 4f 44 43 41 53 54 5f 49 4e 46 4f 47 } //00 00  UP_MESSAGE_BRODCAST_INFOG
	condition:
		any of ($a_*)
 
}