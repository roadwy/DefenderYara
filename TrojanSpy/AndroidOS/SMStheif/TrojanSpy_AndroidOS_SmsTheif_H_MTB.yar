
rule TrojanSpy_AndroidOS_SmsTheif_H_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsTheif.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 61 78 5f 53 6d 73 5f 54 69 6d 65 } //01 00  Max_Sms_Time
		$a_00_1 = {4c 61 73 74 5f 53 6d 73 5f 4b 65 79 } //01 00  Last_Sms_Key
		$a_00_2 = {58 4d 53 2e 41 50 50 } //01 00  XMS.APP
		$a_00_3 = {66 38 61 62 32 63 65 63 61 39 31 36 33 37 32 34 62 36 64 31 32 36 61 65 61 39 36 32 30 33 33 39 } //01 00  f8ab2ceca9163724b6d126aea9620339
		$a_00_4 = {67 65 74 53 69 6d 53 65 72 69 61 6c 4e 75 6d 62 65 72 } //01 00  getSimSerialNumber
		$a_00_5 = {67 65 74 4f 72 69 67 69 6e 61 74 69 6e 67 41 64 64 72 65 73 73 } //00 00  getOriginatingAddress
	condition:
		any of ($a_*)
 
}