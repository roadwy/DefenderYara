
rule TrojanClicker_BAT_Keywsec_B{
	meta:
		description = "TrojanClicker:BAT/Keywsec.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 00 6c 00 69 00 63 00 6b 00 73 00 4f 00 6e 00 53 00 69 00 74 00 65 00 } //01 00  clicksOnSite
		$a_01_1 = {74 00 69 00 6d 00 65 00 4f 00 6e 00 53 00 69 00 74 00 65 00 } //01 00  timeOnSite
		$a_01_2 = {66 00 65 00 61 00 74 00 75 00 72 00 65 00 73 00 2f 00 67 00 65 00 74 00 2f 00 6e 00 65 00 77 00 2f 00 6d 00 61 00 63 00 2f 00 } //01 00  features/get/new/mac/
		$a_01_3 = {6a 00 6f 00 62 00 73 00 2f 00 73 00 65 00 74 00 2f 00 69 00 6d 00 61 00 67 00 65 00 2f 00 69 00 6e 00 64 00 65 00 78 00 2e 00 70 00 68 00 70 00 } //01 00  jobs/set/image/index.php
		$a_01_4 = {61 00 48 00 52 00 30 00 63 00 44 00 6f 00 76 00 } //01 00  aHR0cDov
		$a_01_5 = {63 00 61 00 6d 00 70 00 61 00 69 00 67 00 6e 00 49 00 64 00 } //00 00  campaignId
		$a_00_6 = {5d 04 00 } //00 4e 
	condition:
		any of ($a_*)
 
}