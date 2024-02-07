
rule TrojanSpy_AndroidOS_SAgnt_AM_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.AM!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {69 6e 2f 61 70 69 2f 73 69 67 6e 75 70 2e 70 68 70 2f } //01 00  in/api/signup.php/
		$a_00_1 = {69 6e 2f 61 70 69 2f 6d 65 73 73 61 67 65 2e 70 68 70 2f } //01 00  in/api/message.php/
		$a_01_2 = {53 63 72 65 65 6e 4f 6e 4f 66 66 42 61 63 6b 67 72 6f 75 6e 64 53 65 72 76 69 63 65 } //01 00  ScreenOnOffBackgroundService
		$a_00_3 = {67 65 74 6c 69 76 65 70 6f 69 6e 74 2e 63 6f } //01 00  getlivepoint.co
		$a_00_4 = {4b 45 59 5f 45 54 55 53 45 52 4e 41 4d 45 } //01 00  KEY_ETUSERNAME
		$a_00_5 = {75 72 65 6d 69 61 } //00 00  uremia
	condition:
		any of ($a_*)
 
}