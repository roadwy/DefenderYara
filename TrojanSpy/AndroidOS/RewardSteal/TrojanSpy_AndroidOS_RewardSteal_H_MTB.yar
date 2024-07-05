
rule TrojanSpy_AndroidOS_RewardSteal_H_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/RewardSteal.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 74 70 73 3a 2f 2f 70 61 6e 65 6c 32 34 37 2e 78 79 7a 2f } //01 00  ttps://panel247.xyz/
		$a_01_1 = {61 70 69 2f 6d 65 73 73 65 67 65 2e 70 68 70 } //01 00  api/messege.php
		$a_01_2 = {63 61 72 64 5f 6e 75 6d 62 65 72 } //01 00  card_number
		$a_01_3 = {61 70 69 2f 69 6e 73 65 72 74 2e 70 68 70 } //00 00  api/insert.php
	condition:
		any of ($a_*)
 
}