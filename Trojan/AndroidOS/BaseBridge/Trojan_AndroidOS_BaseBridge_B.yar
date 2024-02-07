
rule Trojan_AndroidOS_BaseBridge_B{
	meta:
		description = "Trojan:AndroidOS/BaseBridge.B,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 61 74 74 65 72 79 2f 42 61 6c 63 6b 41 63 74 69 76 69 74 79 32 } //01 00  battery/BalckActivity2
		$a_01_1 = {4b 69 6c 6c 54 68 72 65 65 53 69 78 5a 65 72 6f } //01 00  KillThreeSixZero
		$a_01_2 = {72 65 63 65 69 76 65 72 2f 52 65 63 65 69 76 65 72 42 6c 61 63 6b 41 63 74 69 76 65 53 74 61 72 74 32 } //01 00  receiver/ReceiverBlackActiveStart2
		$a_01_3 = {2f 62 61 74 74 65 72 79 2f 42 72 69 64 67 65 50 72 6f 76 69 64 65 72 } //01 00  /battery/BridgeProvider
		$a_01_4 = {68 61 73 4e 6f 74 49 6e 73 74 61 6c 6c 65 64 5f 33 36 30 20 3a } //01 00  hasNotInstalled_360 :
		$a_01_5 = {73 6c 34 61 72 50 30 52 63 44 } //00 00  sl4arP0RcD
	condition:
		any of ($a_*)
 
}