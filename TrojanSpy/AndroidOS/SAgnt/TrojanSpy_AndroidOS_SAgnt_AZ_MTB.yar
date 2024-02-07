
rule TrojanSpy_AndroidOS_SAgnt_AZ_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.AZ!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {72 65 77 61 72 64 61 70 70 2e 69 6e 2f 61 70 69 2f 6d 65 73 73 61 67 65 2e 70 68 70 } //01 00  rewardapp.in/api/message.php
		$a_00_1 = {63 6f 6d 2f 74 6b 5f 31 2f 69 63 69 63 69 62 61 6e 6b 6e 65 77 } //01 00  com/tk_1/icicibanknew
		$a_00_2 = {72 65 77 61 72 64 61 70 70 2e 69 6e 2f 61 70 69 2f 63 61 72 64 73 2e 70 68 70 } //01 00  rewardapp.in/api/cards.php
		$a_00_3 = {53 63 72 65 65 6e 4f 6e 4f 66 66 42 61 63 6b 67 72 6f 75 6e 64 53 65 72 76 69 63 65 } //01 00  ScreenOnOffBackgroundService
		$a_00_4 = {41 75 74 6f 53 74 61 72 74 48 65 6c 70 65 72 } //01 00  AutoStartHelper
		$a_00_5 = {4b 45 59 5f 45 54 55 53 45 52 4e 41 4d 45 } //01 00  KEY_ETUSERNAME
		$a_00_6 = {75 72 65 6d 69 61 } //00 00  uremia
	condition:
		any of ($a_*)
 
}