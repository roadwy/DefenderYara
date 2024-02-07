
rule Trojan_AndroidOS_BRats_A_MTB{
	meta:
		description = "Trojan:AndroidOS/BRats.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 6f 72 63 68 65 73 74 72 61 2e 77 61 74 63 68 64 6f 67 } //01 00  com.orchestra.watchdog
		$a_01_1 = {4e 75 62 61 6e 6b 46 61 63 61 64 65 42 69 6c 6c } //01 00  NubankFacadeBill
		$a_01_2 = {66 61 6b 65 50 72 69 63 65 } //01 00  fakePrice
		$a_01_3 = {50 61 79 6d 65 6e 74 48 69 6a 61 72 6b 54 61 73 6b } //00 00  PaymentHijarkTask
	condition:
		any of ($a_*)
 
}