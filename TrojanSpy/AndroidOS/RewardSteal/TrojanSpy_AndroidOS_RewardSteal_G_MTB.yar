
rule TrojanSpy_AndroidOS_RewardSteal_G_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/RewardSteal.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 74 70 73 3a 2f 2f 66 69 6c 69 70 6b 61 74 72 74 2e 69 6e 2f 61 64 6d 69 6e } //01 00  ttps://filipkatrt.in/admin
		$a_01_1 = {4d 65 73 73 61 67 65 52 65 73 65 76 65 72 } //01 00  MessageResever
		$a_01_2 = {70 75 73 73 77 6f 72 64 } //01 00  pussword
		$a_01_3 = {63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 62 69 6c 6c 5f 75 70 64 61 74 65 74 72 79 67 72 65 65 72 74 33 35 34 72 74 35 33 34 74 } //00 00  com/example/bill_updatetrygreert354rt534t
	condition:
		any of ($a_*)
 
}