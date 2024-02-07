
rule Trojan_AndroidOS_BankerBel_A{
	meta:
		description = "Trojan:AndroidOS/BankerBel.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {67 61 6d 62 6c 65 5f 75 72 6c } //02 00  gamble_url
		$a_01_1 = {57 68 61 74 53 63 61 6e 32 30 32 32 5f } //02 00  WhatScan2022_
		$a_01_2 = {73 74 61 72 74 5f 77 6f 72 6b 5f 6d 65 3a 20 74 68 72 65 61 64 3a 20 6b 6e 6f 63 6b 69 6e 67 2e 2e 2e } //00 00  start_work_me: thread: knocking...
	condition:
		any of ($a_*)
 
}