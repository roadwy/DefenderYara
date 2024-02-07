
rule Trojan_AndroidOS_FakeGuard_A{
	meta:
		description = "Trojan:AndroidOS/FakeGuard.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 65 6e 64 4d 65 73 73 61 67 65 28 29 20 43 6f 6e 6e 65 63 74 20 45 72 72 6f 72 21 21 } //01 00  SendMessage() Connect Error!!
		$a_01_1 = {53 4d 53 20 46 72 6f 6d 31 3a } //01 00  SMS From1:
		$a_01_2 = {52 65 73 65 74 69 6e 67 3a } //01 00  Reseting:
		$a_01_3 = {53 70 61 6d 42 6c 6f 63 6b 65 72 } //00 00  SpamBlocker
	condition:
		any of ($a_*)
 
}