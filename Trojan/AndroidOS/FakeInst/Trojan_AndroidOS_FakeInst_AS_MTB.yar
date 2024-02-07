
rule Trojan_AndroidOS_FakeInst_AS_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeInst.AS!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 74 61 72 74 53 4d 53 4d 6f 6e 69 74 6f 72 69 6e 67 } //01 00  startSMSMonitoring
		$a_00_1 = {73 6d 73 5f 63 6f 6d 70 6f 73 65 72 } //01 00  sms_composer
		$a_01_2 = {53 49 4d 5f 53 54 41 54 45 5f 50 49 4e 5f 52 45 51 55 49 52 45 44 } //01 00  SIM_STATE_PIN_REQUIRED
		$a_00_3 = {73 65 6e 64 5f 69 6e 73 74 61 6c 6c 65 64 } //01 00  send_installed
		$a_00_4 = {53 6d 61 72 74 43 6c 65 61 6e 65 72 2e 61 70 6b } //01 00  SmartCleaner.apk
		$a_00_5 = {6d 6f 73 65 6e 74 2e 70 68 70 } //00 00  mosent.php
		$a_00_6 = {5d 04 00 00 } //d3 91 
	condition:
		any of ($a_*)
 
}