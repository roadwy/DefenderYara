
rule Trojan_AndroidOS_SAgnt_AZ_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.AZ!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4d 53 54 6f 4d 61 70 41 63 74 69 76 69 74 79 } //01 00  SMSToMapActivity
		$a_01_1 = {2f 73 64 63 61 72 64 2f 42 69 6b 69 6e 67 44 61 74 61 2f 6d 79 6c 6f 63 } //01 00  /sdcard/BikingData/myloc
		$a_01_2 = {73 6d 73 5f 73 65 6c 65 63 74 43 6f 6e 74 61 63 74 } //01 00  sms_selectContact
		$a_01_3 = {70 6f 69 5f 73 6d 73 5f 6c 61 74 } //00 00  poi_sms_lat
	condition:
		any of ($a_*)
 
}