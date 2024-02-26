
rule Trojan_AndroidOS_SAgnt_AY_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.AY!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 73 6f 66 74 77 61 72 65 2e 61 70 70 } //01 00  com.software.app
		$a_01_1 = {73 6d 73 5f 74 65 78 74 } //01 00  sms_text
		$a_01_2 = {44 65 76 69 63 65 52 65 67 69 73 74 72 61 72 } //01 00  DeviceRegistrar
		$a_01_3 = {53 45 4e 54 5f 53 4d 53 5f 4e 55 4d 42 45 52 5f 4b 45 59 } //01 00  SENT_SMS_NUMBER_KEY
		$a_01_4 = {4f 46 46 45 52 54 5f 41 43 54 49 56 49 54 59 } //01 00  OFFERT_ACTIVITY
		$a_01_5 = {61 72 65 49 6e 73 74 61 6c 6c 65 64 41 6e 64 41 63 74 65 64 4c 69 6e 6b 73 45 71 75 61 6c 73 } //00 00  areInstalledAndActedLinksEquals
	condition:
		any of ($a_*)
 
}